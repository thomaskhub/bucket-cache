package ui_test

// Browser test for the web UI (acceptance criterion 9): first login with
// forced TOTP enrolment and password change, login with password + TOTP,
// token creation with copy-once display, and revocation.
//
// It drives a headless Chromium through chromedp and skips when none is
// found. Set CHROME_PATH to pick a browser; otherwise it looks in
// $PLAYWRIGHT_BROWSERS_PATH and on $PATH (google-chrome, chromium). CI
// runners with Chrome installed (ubuntu-latest has it) run it as part of
// `go test ./...`; YPROXY_BROWSER_TEST=require makes a missing browser fail.

import (
	"context"
	"encoding/base32"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cdplog "github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/api"
	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/cache"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/gitmirror"
	"github.com/thomaskhub/bucket-cache/internal/s3proxy"
	"github.com/thomaskhub/bucket-cache/internal/store"
	"github.com/thomaskhub/bucket-cache/internal/ui"
	"github.com/thomaskhub/bucket-cache/internal/users"
)

func findChrome() string {
	if p := os.Getenv("CHROME_PATH"); p != "" {
		return p
	}
	if dir := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); dir != "" {
		for _, pat := range []string{"chromium-*/chrome-linux*/chrome", "chromium_headless_shell-*/chrome-linux*/headless_shell"} {
			if m, _ := filepath.Glob(filepath.Join(dir, pat)); len(m) > 0 {
				return m[len(m)-1]
			}
		}
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

type fakeBackend struct{}

func (fakeBackend) Get(context.Context, string, s3proxy.Conditions) (*s3proxy.Object, error) {
	return nil, s3proxy.ErrNotFound
}
func (fakeBackend) Head(context.Context, string, s3proxy.Conditions) (*s3proxy.Object, error) {
	return nil, s3proxy.ErrNotFound
}
func (fakeBackend) Test(context.Context) error { return nil }

// newGitUpstream serves a bare repo acme/app with `git http-backend`, like
// a tiny GitHub, and returns its base URL.
func newGitUpstream(t *testing.T) string {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	// The test servers are on 127.0.0.1; don't send git through a proxy.
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(k, "")
	}
	root, home := t.TempDir(), t.TempDir()
	env := []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com"}
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir, cmd.Env = dir, append(env, "PATH="+os.Getenv("PATH"))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	bare := filepath.Join(root, "acme", "app.git")
	git("", "init", "--quiet", "--bare", "--initial-branch=main", bare)
	work := t.TempDir()
	git(work, "init", "--quiet", "--initial-branch=main")
	os.WriteFile(filepath.Join(work, "README"), []byte("hello\n"), 0o600)
	git(work, "add", "-A")
	git(work, "commit", "--quiet", "-m", "first")
	git(work, "push", "--quiet", bare, "main")
	h := &cgi.Handler{Path: gitBin, Args: []string{"http-backend"}, Stderr: io.Discard,
		Env: append(env, "GIT_PROJECT_ROOT="+root, "GIT_HTTP_EXPORT_ALL=1")}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// fakeS3 serves GetObject/HeadObject for one path-style bucket "b".
type fakeS3 map[string]string

func (f fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key, ok := strings.CutPrefix(r.URL.Path, "/b/")
	data, found := f[key]
	if !ok || !found {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		if r.Method != http.MethodHead {
			io.WriteString(w, `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>x</Message></Error>`)
		}
		return
	}
	w.Header().Set("ETag", `"`+key+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		io.WriteString(w, data)
	}
}

type offsetClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *offsetClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return time.Now().Add(c.off) }
func (c *offsetClock) Add(d time.Duration) { c.mu.Lock(); c.off += d; c.mu.Unlock() }

func TestBrowserLoginAndTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("browser test skipped in -short mode")
	}
	chrome := findChrome()
	if chrome == "" {
		if os.Getenv("YPROXY_BROWSER_TEST") == "require" {
			t.Fatal("no Chrome or Chromium found (set CHROME_PATH)")
		}
		t.Skip("no Chrome or Chromium found; set CHROME_PATH to run the browser test")
	}
	auth.PasswordParams = auth.Argon2Params{Memory: 64, Time: 1, Threads: 1}

	// Server: API with users plus the UI, as on the admin listener.
	dir := t.TempDir()
	sec := filepath.Join(dir, "s")
	os.WriteFile(sec, []byte("SECRET"), 0o600)
	upstream := newGitUpstream(t)
	s3 := httptest.NewServer(fakeS3{"a/one": strings.Repeat("1", 1000), "a/two": strings.Repeat("2", 2000), "b/three": "3"})
	defer s3.Close()
	cfg, err := config.Parse([]byte(`
server: { public_base_url: "http://cache.lan:8080" }
buckets:
  - alias: sstate
    provider: generic
    endpoint: http://s3.lan
    bucket: b
    credentials: { access_key_id: { file: `+sec+` }, secret_access_key: { file: `+sec+` } }
  - alias: cached
    provider: generic
    endpoint: `+s3.URL+`
    bucket: b
    credentials: { access_key_id: { file: `+sec+` }, secret_access_key: { file: `+sec+` } }
    mode: cache
    cache: { max_size: 1MiB }
storage: { cache_root: `+filepath.Join(dir, "cache")+` }
git:
  storage: `+filepath.Join(dir, "git")+`
  remotes:
    - name: test
      url: `+upstream+`
      allow: ["acme/*"]
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), filepath.Join(dir, "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	mirrors, err := gitmirror.New(context.Background(), cfg.Git, gitmirror.Options{PublicBaseURL: cfg.Server.PublicBaseURL, AllowStore: st})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authn := auth.New(st, log, "", time.Second)
	sealer, _ := auth.NewSealer("browser-test-master-key-1234")
	svc := users.New(st, sealer, log, users.Options{})
	clk := &offsetClock{}
	svc.Now = clk.Now
	if _, err := svc.Bootstrap(context.Background(), "admin", "initial-password-1"); err != nil {
		t.Fatal(err)
	}
	caches, err := cache.OpenAll(cfg, log, prometheus.NewRegistry())
	if err != nil {
		t.Fatal(err)
	}
	defer cache.CloseAll(caches)
	backends := map[string]s3proxy.Backend{"sstate": fakeBackend{}, "cached": s3proxy.NewS3Backend(cfg.Buckets[1])}
	objects := s3proxy.NewHandler(backends, authn, log, prometheus.NewRegistry(), false)
	objects.SetCache("cached", caches["cached"])
	mux := http.NewServeMux()
	apiSrv := api.New(cfg, st, authn, backends, log).WithUsers(svc).WithCaches(caches)
	apiSrv.Register(mux)
	mirrors.RegisterAPI(mux, apiSrv.Authenticated, apiSrv.AdminOnly)
	mirrors.RegisterAllowAPI(mux, apiSrv.AdminActor)
	h, err := ui.New()
	if err != nil {
		t.Fatal(err)
	}
	h.Register(mux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if objects.Match(r.URL.Path) { // the data plane, for filling the cache
			objects.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()

	// Browser.
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome), chromedp.NoSandbox,
		chromedp.Flag("disable-dev-shm-usage", true))
	actx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(actx)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 90*time.Second)
	defer cancelTimeout()

	// Any script error or CSP violation fails the test.
	if err := chromedp.Do(ctx, chromedp.Navigate("about:blank")); err != nil {
		t.Fatalf("starting %s: %v", chrome, err)
	}
	var jsMu sync.Mutex
	var jsErrors []string
	addErr := func(s string) { jsMu.Lock(); jsErrors = append(jsErrors, s); jsMu.Unlock() }
	exceptions := chromedp.Events(ctx, runtime.ExceptionThrown)
	console := chromedp.Events(ctx, runtime.ConsoleAPICalled)
	logEntries := chromedp.Events(ctx, cdplog.EntryAdded) // CSP violations are reported here
	go func() {
		for ev, err := range logEntries {
			if err != nil {
				return
			}
			// Failed requests (the 401 before login) are expected; script, CSP and
			// other problems are not.
			if ev.Entry.Source != cdplog.EntrySourceNetwork && (ev.Entry.Level == cdplog.EntryLevelError || ev.Entry.Level == cdplog.EntryLevelWarning) {
				addErr(string(ev.Entry.Source) + ": " + ev.Entry.Text + " " + ev.Entry.URL)
			}
		}
	}()
	go func() {
		for ev, err := range exceptions {
			if err != nil {
				return
			}
			d := ev.ExceptionDetails
			msg := d.Text
			if d.Exception != nil {
				msg += " " + d.Exception.Description
			}
			addErr(msg)
		}
	}()
	go func() {
		for ev, err := range console {
			if err != nil {
				return
			}
			if ev.Type == runtime.ConsoleAPICalledTypeError || ev.Type == runtime.ConsoleAPICalledTypeWarning {
				var parts []string
				for _, a := range ev.Args {
					parts = append(parts, string(a.Value)+a.Description)
				}
				addErr(strings.Join(parts, " "))
			}
		}
	}()
	fail := func(step string, err error) {
		t.Helper()
		html, _ := chromedp.Run(ctx, chromedp.OuterHTML(chromedp.CSS("main")))
		jsMu.Lock()
		defer jsMu.Unlock()
		t.Fatalf("%s: %v\njs errors: %v\nmain: %s", step, err, jsErrors, html)
	}
	run := func(step string, actions ...chromedp.Action[chromedp.Void]) {
		t.Helper()
		if err := chromedp.Do(ctx, actions...); err != nil {
			fail(step, err)
		}
	}
	text := func(sel string) string {
		t.Helper()
		v, err := chromedp.Run(ctx, chromedp.Text(chromedp.CSS(sel)))
		if err != nil {
			fail("read "+sel, err)
		}
		return strings.TrimSpace(v)
	}
	// YPROXY_UI_SCREENSHOTS=dir saves a screenshot after each step.
	shots := os.Getenv("YPROXY_UI_SCREENSHOTS")
	shot := func(name string) {
		if shots == "" {
			return
		}
		if b, err := chromedp.Run(ctx, chromedp.FullScreenshot(80)); err == nil {
			_ = os.WriteFile(filepath.Join(shots, name+".jpg"), b, 0o600)
		}
	}
	code := func(secret []byte) string { return auth.TOTPCode(secret, auth.TOTPStep(clk.Now())) }

	// 1. First login with the initial password only: forced TOTP enrolment.
	run("open login page",
		chromedp.Navigate(srv.URL+"/"),
		chromedp.WaitVisible(chromedp.CSS(`#login-form`)),
	)
	banner, err := chromedp.Run(ctx, chromedp.Evaluate[bool](`document.getElementById('http-warning').offsetParent !== null`))
	if err != nil || !banner {
		t.Error("plain-HTTP warning not shown")
	}
	run("first login",
		chromedp.SendKeys(chromedp.CSS(`#login-form input[name=username]`), "admin"),
		chromedp.SendKeys(chromedp.CSS(`#login-form input[name=password]`), "initial-password-1"),
		chromedp.Click(chromedp.CSS(`#login-form button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`#enrol`)),
	)
	run("show enrolment", chromedp.WaitVisible(chromedp.CSS(`#totp-qr`)))
	qr, err := chromedp.Run(ctx, chromedp.AttributeValue(chromedp.CSS(`#totp-qr`), "src"))
	if err != nil || !strings.HasPrefix(qr.Value, "data:image/png;base64,") {
		t.Fatalf("QR src = %.40q, %v", qr.Value, err)
	}
	run("show key", chromedp.Click(chromedp.CSS(`#enrol button[type=button]`)), chromedp.WaitVisible(chromedp.CSS(`#totp-secret`)))
	secretText := text(`#totp-secret`)
	shot("1-enrol")
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimSpace(secretText))
	if err != nil {
		t.Fatalf("TOTP secret %q: %v", secretText, err)
	}
	run("confirm enrolment",
		chromedp.SendKeys(chromedp.CSS(`#enrol-form input[name=code]`), code(secret)),
		chromedp.Click(chromedp.CSS(`#enrol-form button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`#password-change`)),
	)
	shot("2-password")

	// 2. Forced password change, then the dashboard.
	run("change password",
		chromedp.SendKeys(chromedp.CSS(`#password-change input[name=current]`), "initial-password-1"),
		chromedp.SendKeys(chromedp.CSS(`#password-change input[name=new]`), "my-own-password-42"),
		chromedp.SendKeys(chromedp.CSS(`#password-change input[name=repeat]`), "my-own-password-42"),
		chromedp.Click(chromedp.CSS(`#password-change button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`a[data-nav=tokens]`)),
		chromedp.WaitVisible(chromedp.CSS(`#stat-tokens`)),
	)

	// 3. Log out and in again with password + TOTP.
	clk.Add(30 * time.Second) // the enrolment code's step is used up
	run("logout", chromedp.Click(chromedp.CSS(`#logout`)), chromedp.WaitVisible(chromedp.CSS(`#login-form`)))
	run("login with TOTP",
		chromedp.SendKeys(chromedp.CSS(`#login-form input[name=username]`), "admin"),
		chromedp.SendKeys(chromedp.CSS(`#login-form input[name=password]`), "my-own-password-42"),
		chromedp.SendKeys(chromedp.CSS(`#login-form input[name=code]`), code(secret)),
		chromedp.Click(chromedp.CSS(`#login-form button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`a[data-nav=users]`)),
	)

	// 4. Create a token: shown once, then it works for the data plane.
	run("create token",
		chromedp.Click(chromedp.CSS(`a[data-nav=tokens]`)),
		chromedp.WaitVisible(chromedp.CSS(`#token-form input[name=bucket-sstate]`)),
		chromedp.SendKeys(chromedp.CSS(`#token-form input[name=description]`), "browser test"),
		chromedp.Click(chromedp.CSS(`#token-form input[name=bucket-sstate]`)),
		chromedp.Click(chromedp.CSS(`#token-form button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`#token-created`)),
	)
	tokenValue := text(`#token-value`)
	shot("3-token-created")
	tok, err := authn.Token(context.Background(), strings.TrimSpace(tokenValue))
	if err != nil || tok.Description != "browser test" || tok.CreatedBy == "" {
		t.Fatalf("created token %q: %+v, %v", tokenValue, tok, err)
	}
	run("dismiss token",
		chromedp.Click(chromedp.CSS(`#token-dismiss`)),
		chromedp.WaitNotVisible(chromedp.CSS(`#token-created`)),
		chromedp.WaitVisible(chromedp.CSS(`#tokens-table tr[data-token]`)),
	)
	stillShown, _ := chromedp.Run(ctx, chromedp.Evaluate[string](`document.body.innerText`))
	if strings.Contains(stillShown, "ybp_") {
		t.Fatal("token value still in the page after dismissing")
	}

	// 5. Revoke (two clicks) and check it stops working.
	run("revoke token",
		chromedp.Click(chromedp.CSS(`#tokens-table button[data-action=revoke]`)),
		chromedp.Click(chromedp.CSS(`#tokens-table button[data-action=revoke]`)),
		chromedp.WaitVisible(chromedp.CSS(`#tokens-empty`)),
	)
	authn.Forget(auth.Hash(strings.TrimSpace(tokenValue)))
	if _, err := authn.Token(context.Background(), strings.TrimSpace(tokenValue)); !errors.Is(err, auth.ErrDead) {
		t.Fatalf("revoked token: %v", err)
	}

	// 6. Create a user; the one-time password is shown once.
	run("create user",
		chromedp.Click(chromedp.CSS(`a[data-nav=users]`)),
		chromedp.WaitVisible(chromedp.CSS(`#user-form`)),
		chromedp.SendKeys(chromedp.CSS(`#user-form input[name=username]`), "dev"),
		chromedp.Click(chromedp.CSS(`#user-form button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`#user-secret`)),
		chromedp.WaitVisible(chromedp.CSS(`#users-table tr[data-user=dev]`)),
	)
	pw := text(`#user-password`)
	shot("4-users")
	if len(strings.TrimSpace(pw)) != 20 {
		t.Fatalf("one-time password %q", pw)
	}
	u, err := st.UserByName(context.Background(), "dev")
	if err != nil || u.Role != "user" || auth.VerifyPassword(u.PasswordHash, strings.TrimSpace(pw)) != nil {
		t.Fatalf("created user: %+v, %v", u, err)
	}

	// 7. Repositories (FR-92): mirror a repo, refresh it, delete it.
	waitText := func(sel, prefix string) {
		t.Helper()
		for i := 0; i < 100; i++ {
			if v, err := chromedp.Run(ctx, chromedp.Evaluate[string](`(document.querySelector('`+sel+`')||{}).innerText||''`)); err == nil && strings.HasPrefix(strings.TrimSpace(v), prefix) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		fail("wait for "+sel+" = "+prefix+"…", errors.New("timeout"))
	}
	run("repos page",
		chromedp.Click(chromedp.CSS(`a[data-nav=repos]`)),
		chromedp.WaitVisible(chromedp.CSS(`#repos-empty`)),
		chromedp.SendKeys(chromedp.CSS(`#repo-form input[name=repo]`), "acme/app"),
		chromedp.Click(chromedp.CSS(`#repo-form button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`#repos-table tr[data-repo="test/acme/app"]`)),
	)
	waitText(`#repos-notice`, "Mirrored test/acme/app")
	shot("6-repos")
	run("refresh repo", chromedp.Click(chromedp.CSS(`#repos-table button[data-action=refresh]`)))
	waitText(`#repos-notice`, "Refreshed test/acme/app")
	run("delete repo",
		chromedp.Click(chromedp.CSS(`#repos-table button[data-action=delete]`)),
		chromedp.Click(chromedp.CSS(`#repos-table button[data-action=delete]`)),
		chromedp.WaitVisible(chromedp.CSS(`#repos-empty`)),
	)
	run("allow pattern",
		chromedp.SendKeys(chromedp.CSS(`#allow-form input[name=pattern]`), "Xilinx/*"),
		chromedp.Click(chromedp.CSS(`#allow-form button[type=submit]`)),
		chromedp.WaitVisible(chromedp.CSS(`.allow-table tr[data-pattern="Xilinx/*"] button[data-action=disallow]`)),
	)
	waitText(`#repos-notice`, "Allowed Xilinx/*")
	waitText(`.allow-table tr[data-pattern="Xilinx/*"] td:nth-child(2)`, "added by admin")
	if !mirrors.Allowed("test", "xilinx", "linux-xlnx") {
		t.Fatal("pattern added in the UI not applied")
	}
	shot("6b-allow")
	run("remove pattern",
		chromedp.Click(chromedp.CSS(`.allow-table tr[data-pattern="Xilinx/*"] button[data-action=disallow]`)),
		chromedp.Click(chromedp.CSS(`.allow-table tr[data-pattern="Xilinx/*"] button[data-action=disallow]`)),
	)
	waitText(`#repos-notice`, "Removed Xilinx/*")
	if mirrors.Allowed("test", "xilinx", "linux-xlnx") {
		t.Fatal("pattern removed in the UI still applied")
	}
	// Without git remotes in the session the nav entry is hidden.
	hidden, err := chromedp.Run(ctx, chromedp.Evaluate[bool](`(function () {
		var a = Alpine.store('app'), s = a.session;
		a.session = Object.assign({}, s, { git_remotes: [] });
		var hidden = !a.nav().some(function (p) { return p.id === 'repos'; });
		a.session = s;
		return hidden;
	})()`))
	if err != nil || !hidden {
		t.Fatalf("repos nav entry without git: hidden=%v err=%v", hidden, err)
	}

	// 8. Cache stats and purge (FR-57, FR-60): fill the cache through the
	// data plane from the fake S3, with one hit.
	ciTok := auth.NewSecret(auth.TokenPrefix)
	now := time.Now()
	if err := st.CreateToken(context.Background(), &store.Token{ID: auth.NewID("tok_"), Hash: auth.Hash(ciTok), Kind: "ci",
		Scope: store.Scope{Buckets: []string{"cached"}}, CreatedBy: "test", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"a/one", "a/two", "b/three", "a/one"} {
		resp, err := http.Get(srv.URL + "/t/" + ciTok + "/cached/" + k)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %s", k, resp.Status)
		}
		for i := 0; i < 500; i++ {
			if _, ok := caches["cached"].Lookup(k); ok {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	run("buckets page", chromedp.Navigate(srv.URL+"/#/buckets"), chromedp.WaitVisible(chromedp.CSS(`section[data-cache=cached]`)))
	waitText(`section[data-cache=cached] [data-stat=objects]`, "3")
	waitText(`section[data-cache=cached] [data-stat=ratio]`, "25.0%")
	waitText(`section[data-cache=cached] [data-stat=usage]`, "2.9 KiB of 1.0 MiB")
	shot("7-cache")
	run("purge key",
		chromedp.SendKeys(chromedp.CSS(`section[data-cache=cached] input[name=purge-key]`), "a/one"),
		chromedp.Click(chromedp.CSS(`section[data-cache=cached] button[data-action=purge-key]`)),
	)
	waitText(`section[data-cache=cached] [data-purge=result]`, "Removed 1 objects")
	waitText(`section[data-cache=cached] [data-stat=objects]`, "2")
	if _, ok := caches["cached"].Lookup("a/one"); ok {
		t.Fatal("a/one still cached after purging it")
	}
	run("purge all, first click", chromedp.Click(chromedp.CSS(`section[data-cache=cached] button[data-action=purge-all]`)))
	waitText(`section[data-cache=cached] button[data-action=purge-all]`, "Click again")
	if _, ok := caches["cached"].Lookup("a/two"); !ok {
		t.Fatal("the first click purged without confirmation")
	}
	run("purge all, confirm", chromedp.Click(chromedp.CSS(`section[data-cache=cached] button[data-action=purge-all]`)))
	waitText(`section[data-cache=cached] [data-purge=result]`, "Removed 2 objects")
	waitText(`section[data-cache=cached] [data-stat=objects]`, "0")
	shot("8-purged")
	run("dashboard", chromedp.Navigate(srv.URL+"/#/dashboard"), chromedp.WaitVisible(chromedp.CSS(`[data-cache-ratio=cached]`)))
	waitText(`[data-cache-ratio=cached] .stat-value`, "25.0%")
	waitText(`#stat-mirrors`, "0")

	// Visit every page once so their scripts run under the CSP.
	for _, p := range []string{"dashboard", "apikeys", "buckets", "repos", "account"} {
		run("page "+p, chromedp.Navigate(srv.URL+"/#/"+p), chromedp.WaitVisible(chromedp.CSS(`main h1`)), chromedp.Sleep(200*time.Millisecond))
		shot("5-" + p)
	}

	jsMu.Lock()
	defer jsMu.Unlock()
	if len(jsErrors) > 0 {
		t.Fatalf("browser reported errors: %v", jsErrors)
	}
}
