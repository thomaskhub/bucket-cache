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
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cdplog "github.com/chromedp/cdproto/log"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/thomaskhub/bucket-cache/internal/api"
	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
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
	cfg, err := config.Parse([]byte(`
server: { public_base_url: "http://cache.lan:8080" }
buckets:
  - alias: sstate
    provider: generic
    endpoint: http://s3.lan
    bucket: b
    credentials: { access_key_id: { file: `+sec+` }, secret_access_key: { file: `+sec+` } }
`), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), filepath.Join(dir, "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	authn := auth.New(st, log, "", time.Second)
	sealer, _ := auth.NewSealer("browser-test-master-key-1234")
	svc := users.New(st, sealer, log, users.Options{})
	clk := &offsetClock{}
	svc.Now = clk.Now
	if _, err := svc.Bootstrap(context.Background(), "admin", "initial-password-1"); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api.New(cfg, st, authn, map[string]s3proxy.Backend{"sstate": fakeBackend{}}, log).WithUsers(svc).Register(mux)
	h, err := ui.New()
	if err != nil {
		t.Fatal(err)
	}
	h.Register(mux)
	srv := httptest.NewServer(mux)
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

	// Visit every page once so their scripts run under the CSP.
	for _, p := range []string{"dashboard", "apikeys", "buckets", "account"} {
		run("page "+p, chromedp.Navigate(srv.URL+"/#/"+p), chromedp.WaitVisible(chromedp.CSS(`main h1`)), chromedp.Sleep(200*time.Millisecond))
		shot("5-" + p)
	}

	jsMu.Lock()
	defer jsMu.Unlock()
	if len(jsErrors) > 0 {
		t.Fatalf("browser reported errors: %v", jsErrors)
	}
}
