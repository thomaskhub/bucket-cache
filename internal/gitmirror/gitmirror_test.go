package gitmirror

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/config"
)

// clientGit runs git as a build host would, with an explicit protocol
// version and no credential helpers.
func clientGit(t *testing.T, proto int, dir string, args ...string) (string, error) {
	t.Helper()
	base := []string{"-c", fmt.Sprintf("protocol.version=%d", proto), "-c", "credential.helper=", "-c", "advice.detachedHead=false"}
	return runGit(t, dir, append(base, args...)...)
}

func mustClient(t *testing.T, proto int, dir string, args ...string) string {
	t.Helper()
	out, err := clientGit(t, proto, dir, args...)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(out)
}

// TestCloneMatrix compares common read operations through the proxy with
// the same operations against upstream directly, for protocol v0 and v2
// (FR-82, acceptance criterion 10).
func TestCloneMatrix(t *testing.T) {
	up := newUpstream(t)
	r := up.newRepo("acme", "meta-acme")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/*")
	prSHA := mustGit(t, r.bare, "rev-parse", "refs/pull/1/head")
	firstSHA := mustGit(t, r.bare, "rev-parse", "main~1")

	for _, proto := range []int{0, 2} {
		t.Run(fmt.Sprintf("v%d", proto), func(t *testing.T) {
			proxyURL := e.url(tok, "acme/meta-acme")
			// Cases: name, extra clone args, refs to compare.
			cases := []struct {
				name string
				args []string
			}{
				{"full", nil},
				{"single-branch", []string{"--single-branch", "--branch", "kirkstone"}},
				{"depth1", []string{"--depth", "1"}},
				{"depth1-branch", []string{"--depth", "1", "--branch", "kirkstone", "--single-branch"}},
				{"partial", []string{"--filter=blob:none"}},
				{"treeless", []string{"--filter=tree:0"}},
				{"bare-mirror", []string{"--mirror"}},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					viaProxy, direct := filepath.Join(t.TempDir(), "p"), filepath.Join(t.TempDir(), "d")
					b0 := e.metric("yproxy_git_bytes_served_total", nil)
					mustClient(t, proto, "", append(append([]string{"clone", "--quiet"}, c.args...), proxyURL, viaProxy)...)
					proxyBytes := e.metric("yproxy_git_bytes_served_total", nil) - b0
					u0 := up.bytes.Load()
					mustClient(t, proto, "", append(append([]string{"clone", "--quiet"}, c.args...), e.direct("acme/meta-acme"), direct)...)
					directBytes := float64(up.bytes.Load() - u0)

					// Same refs, minus GitHub's PR refs that the mirror leaves out (FR-83).
					got, want := refs(t, viaProxy), refs(t, direct)
					want = dropLines(want, "refs/pull/")
					if got != want {
						t.Fatalf("refs differ\nproxy:\n%s\ndirect:\n%s", got, want)
					}
					if strings.Contains(got, "refs/proxy/") {
						t.Fatalf("hidden refs leaked: %s", got)
					}
					if c.name != "bare-mirror" {
						if a, b := mustGit(t, viaProxy, "rev-parse", "HEAD"), mustGit(t, direct, "rev-parse", "HEAD"); a != b {
							t.Fatalf("HEAD %s != %s", a, b)
						}
					}
					// About the same transfer (acceptance 10: within 10 %).
					if proxyBytes > directBytes*1.1+1024 {
						t.Fatalf("proxy sent %.0f bytes, upstream %.0f", proxyBytes, directBytes)
					}
					if strings.HasPrefix(c.name, "partial") {
						if n := countMissing(t, viaProxy); n == 0 || n != countMissing(t, direct) {
							t.Fatalf("partial clone: %d missing blobs via proxy, %d direct", n, countMissing(t, direct))
						}
						// Lazy fetch of a missing blob through the proxy (sparse checkout path).
						mustClient(t, proto, viaProxy, "cat-file", "-p", "main~1:big.bin")
					}
					if strings.HasPrefix(c.name, "depth1") {
						if n := mustGit(t, viaProxy, "rev-list", "--count", "HEAD"); n != "1" {
							t.Fatalf("depth 1 clone has %s commits", n)
						}
						// --deepen and --unshallow through the proxy.
						mustClient(t, proto, viaProxy, "fetch", "--quiet", "--deepen=1")
						mustClient(t, proto, viaProxy, "fetch", "--quiet", "--unshallow")
					}
				})
			}

			t.Run("ls-remote", func(t *testing.T) {
				got := mustClient(t, proto, "", "ls-remote", proxyURL)
				want := dropLines(mustClient(t, proto, "", "ls-remote", e.direct("acme/meta-acme")), "refs/pull/")
				if got != want {
					t.Fatalf("ls-remote differs\nproxy:\n%s\ndirect:\n%s", got, want)
				}
				tags := mustClient(t, proto, "", "ls-remote", "--tags", proxyURL)
				if !strings.Contains(tags, "refs/tags/v1.0") || !strings.Contains(tags, "refs/tags/v1.1^{}") {
					t.Fatalf("tags: %s", tags)
				}
			})

			t.Run("fetch-by-sha-and-refspec", func(t *testing.T) {
				dir := t.TempDir()
				mustGit(t, dir, "init", "--quiet")
				mustClient(t, proto, dir, "fetch", "--quiet", proxyURL, firstSHA)
				if got := mustGit(t, dir, "rev-parse", "FETCH_HEAD"); got != firstSHA {
					t.Fatalf("FETCH_HEAD = %s", got)
				}
				mustClient(t, proto, dir, "fetch", "--quiet", proxyURL, "refs/heads/kirkstone:refs/remotes/x/kirkstone", "refs/tags/v1.1:refs/tags/v1.1")
				if got := mustGit(t, dir, "rev-parse", "refs/remotes/x/kirkstone"); got != mustGit(t, r.bare, "rev-parse", "kirkstone") {
					t.Fatal("custom refspec fetched the wrong commit")
				}
				// A PR commit isn't on any mirrored ref: fetched by SHA and kept (FR-85).
				mustClient(t, proto, dir, "fetch", "--quiet", proxyURL, prSHA)
				if got := mustGit(t, dir, "rev-parse", "FETCH_HEAD"); got != prSHA {
					t.Fatalf("PR FETCH_HEAD = %s", got)
				}
			})

			t.Run("pull", func(t *testing.T) {
				dir := filepath.Join(t.TempDir(), "c")
				mustClient(t, proto, "", "clone", "--quiet", "--branch", "kirkstone", proxyURL, dir)
				mustClient(t, proto, dir, "-c", "pull.rebase=false", "pull", "--quiet")
			})
		})
	}
}

func dropLines(s, substr string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.Contains(l, substr) {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

func countMissing(t *testing.T, dir string) int {
	out := mustGit(t, dir, "rev-list", "--objects", "--missing=print", "--all")
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "?") {
			n++
		}
	}
	return n
}

// TestFreshness checks that a branch or commit pushed upstream is visible
// through the proxy on the next request after ls_remote_cache (FR-84).
func TestFreshness(t *testing.T) {
	up := newUpstream(t)
	r := up.newRepo("acme", "app")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/*")
	u := e.url(tok, "acme/app")

	for _, proto := range []int{0, 2} {
		mustClient(t, proto, "", "ls-remote", u) // creates the mirror
		r.write("new.txt", fmt.Sprint(time.Now().UnixNano()))
		sha := r.commit(fmt.Sprintf("srcrev v%d", proto))
		branch := fmt.Sprintf("feature-v%d", proto)
		r.push("HEAD:refs/heads/" + branch)
		time.Sleep(250 * time.Millisecond) // > ls_remote_cache (200ms)

		out := mustClient(t, proto, "", "ls-remote", u, "refs/heads/"+branch)
		if !strings.HasPrefix(out, sha) {
			t.Fatalf("v%d: new branch not visible: %q", proto, out)
		}
		// And the commit can be fetched straight away, like BitBake's SRCREV check.
		dir := t.TempDir()
		mustGit(t, dir, "init", "--quiet")
		mustClient(t, proto, dir, "fetch", "--quiet", u, "refs/heads/"+branch)
		if got := mustGit(t, dir, "rev-parse", "FETCH_HEAD"); got != sha {
			t.Fatalf("v%d: fetched %s, want %s", proto, got, sha)
		}
	}
	if e.metric("yproxy_git_ls_remote_total", map[string]string{"result": "changed"}) < 2 {
		t.Fatal("expected changed ls-remote results")
	}

	// Within ls_remote_cache, requests reuse the last check.
	hits := e.metric("yproxy_git_ls_remote_total", map[string]string{"result": "cache_hit"})
	mustClient(t, 2, "", "ls-remote", u)
	mustClient(t, 2, "", "ls-remote", u)
	if e.metric("yproxy_git_ls_remote_total", map[string]string{"result": "cache_hit"}) <= hits {
		t.Fatal("expected an ls-remote cache hit")
	}

	// A branch deleted upstream is pruned (FR-88).
	mustGit(t, r.work, "push", "--quiet", r.bare, ":refs/heads/feature-v0")
	time.Sleep(250 * time.Millisecond)
	if out := mustClient(t, 2, "", "ls-remote", u, "refs/heads/feature-v0"); out != "" {
		t.Fatalf("deleted branch still advertised: %q", out)
	}

	// A second clone with unchanged refs doesn't fetch from upstream.
	fetches := e.metric("yproxy_git_upstream_fetches_total", nil)
	time.Sleep(250 * time.Millisecond)
	mustClient(t, 2, "", "clone", "--quiet", u, filepath.Join(t.TempDir(), "c"))
	if got := e.metric("yproxy_git_upstream_fetches_total", nil); got != fetches {
		t.Fatalf("second clone fetched from upstream (%v -> %v)", fetches, got)
	}
}

// TestKeepRefs checks FR-85: a commit on no branch, fetched by SHA, is kept
// under refs/proxy/keep/, isn't advertised, and survives upstream losing it.
func TestKeepRefs(t *testing.T) {
	up := newUpstream(t)
	r := up.newRepo("acme", "app")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/*")
	u := e.url(tok, "acme/app")

	// A commit that was on a branch and is force-pushed away before the
	// mirror ever saw it.
	mustGit(t, r.work, "checkout", "--quiet", "-b", "tmp")
	r.write("tmp.txt", "gone\n")
	gone := r.commit("force-pushed away")
	r.push("tmp")
	mustGit(t, r.work, "checkout", "--quiet", "main")
	mustGit(t, r.work, "push", "--quiet", r.bare, ":refs/heads/tmp")
	prSHA := mustGit(t, r.bare, "rev-parse", "refs/pull/1/head")

	for i, sha := range []string{gone, prSHA} {
		dir := t.TempDir()
		mustGit(t, dir, "init", "--quiet")
		mustClient(t, i*2, dir, "fetch", "--quiet", u, sha) // v0 then v2
		if got := mustGit(t, dir, "rev-parse", "FETCH_HEAD"); got != sha {
			t.Fatalf("fetched %s, want %s", got, sha)
		}
	}
	mi, _ := e.mgr.mirror("test", "acme", "app")
	kept := mustGit(t, "", "--git-dir="+mi.dir, "for-each-ref", "--format=%(refname)", "refs/proxy/keep/")
	for _, sha := range []string{gone, prSHA} {
		if !strings.Contains(kept, keepPrefix+sha) {
			t.Fatalf("%s not kept: %q", sha, kept)
		}
	}
	for _, proto := range []int{0, 2} {
		if out := mustClient(t, proto, "", "ls-remote", u); strings.Contains(out, "refs/proxy") || strings.Contains(out, prSHA) {
			t.Fatalf("v%d: keep refs advertised:\n%s", proto, out)
		}
	}

	// Upstream drops the PR ref and garbage-collects: the proxy still has it.
	mustGit(t, r.work, "push", "--quiet", r.bare, ":refs/pull/1/head")
	mustGit(t, r.bare, "reflog", "expire", "--expire=now", "--all")
	mustGit(t, r.bare, "gc", "--quiet", "--prune=now")
	if _, err := runGit(t, r.bare, "cat-file", "-e", prSHA); err == nil {
		t.Fatal("upstream still has the PR commit")
	}
	// Proxy-side maintenance must not lose it either.
	e.mgr.Maintain(t.Context())
	mustGit(t, "", "--git-dir="+mi.dir, "gc", "--quiet", "--prune=now")
	dir := t.TempDir()
	mustGit(t, dir, "init", "--quiet")
	mustClient(t, 2, dir, "fetch", "--quiet", u, prSHA)

	// A SHA that exists nowhere fails cleanly.
	if _, err := clientGit(t, 2, dir, "fetch", "--quiet", u, strings.Repeat("ab", 20)); err == nil {
		t.Fatal("fetch of unknown SHA succeeded")
	}
}

// TestAuth covers FR-7, FR-81 and FR-90: challenges, the token forms,
// scopes, the allowlist, push and dead tokens.
func TestAuth(t *testing.T) {
	up := newUpstream(t)
	up.newRepo("acme", "app")
	up.newRepo("acme", "private")
	up.newRepo("other", "x")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/app")
	refsPath := "/git/test/acme/app.git/info/refs?service=git-upload-pack"

	// No credentials: 401 with a Basic challenge (never 404), even for repos outside the allowlist.
	for _, p := range []string{refsPath, "/git/test/other/x/info/refs?service=git-upload-pack", "/git/nope/a/b/info/refs?service=git-upload-pack"} {
		resp, _ := e.do("GET", p, nil, nil)
		if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("%s: %d %q", p, resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}
	// Bearer, Basic (any user) and path token.
	for name, hdr := range map[string]map[string]string{
		"bearer": {"Authorization": "Bearer " + tok},
		"basic":  {"Authorization": "Basic " + b64("anyone:"+tok)},
	} {
		if resp, _ := e.do("GET", refsPath, hdr, nil); resp.StatusCode != 200 {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
	resp, body := e.do("GET", "/t/"+tok+"//git/test//ACME/App/info/refs?service=git-upload-pack", nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-git-upload-pack-advertisement" ||
		!strings.HasPrefix(body, "001e# service=git-upload-pack\n0000") {
		t.Fatalf("path token, mixed case, // : %d %q", resp.StatusCode, body[:min(len(body), 60)])
	}

	// git itself: Basic after the challenge, from user:token in the URL.
	for _, proto := range []int{0, 2} {
		mustClient(t, proto, "", "clone", "--quiet", e.basicURL(tok, "acme/app"), filepath.Join(t.TempDir(), "c"))
		mustClient(t, proto, "", "clone", "--quiet", e.url(tok, "acme/app"), filepath.Join(t.TempDir(), "c"))
	}

	// Out of the token's scope: 403. Outside the allowlist: 404.
	if resp, _ := e.do("GET", "/t/"+tok+"/git/test/acme/private/info/refs?service=git-upload-pack", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("out of scope: %d", resp.StatusCode)
	}
	wide := e.token("acme/*", "other/*")
	for _, p := range []string{"/git/test/other/x/info/refs?service=git-upload-pack", "/git/nope/acme/app/info/refs?service=git-upload-pack"} {
		if resp, _ := e.do("GET", "/t/"+wide+p, nil, nil); resp.StatusCode != 404 {
			t.Fatalf("%s not allowlisted: %d", p, resp.StatusCode)
		}
	}
	if _, err := clientGit(t, 2, "", "ls-remote", e.url(tok, "acme/private")); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("git ls-remote out of scope: %v", err)
	}
	// Allowed but missing upstream: 404, and no mirror entry is left behind.
	if resp, _ := e.do("GET", "/t/"+wide+"/git/test/acme/nope/info/refs?service=git-upload-pack", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("missing upstream repo: %d", resp.StatusCode)
	}
	if mi, _ := e.mgr.mirror("test", "acme", "nope"); mi.isPresent() {
		t.Fatal("mirror created for a missing repo")
	}

	// Push is rejected with 403, before and after authentication.
	for _, p := range []string{"/git/test/acme/app.git/info/refs?service=git-receive-pack", "/git/test/acme/app.git/git-receive-pack"} {
		if resp, _ := e.do("GET", "/t/"+tok+p, nil, nil); resp.StatusCode != 403 {
			t.Fatalf("push %s: %d", p, resp.StatusCode)
		}
	}
	work := filepath.Join(t.TempDir(), "w")
	mustClient(t, 2, "", "clone", "--quiet", e.url(tok, "acme/app"), work)
	if _, err := clientGit(t, 2, work, "push", e.url(tok, "acme/app"), "HEAD:refs/heads/evil"); err == nil {
		t.Fatal("push succeeded")
	}
	// Dumb HTTP isn't served.
	if resp, _ := e.do("GET", "/t/"+tok+"/git/test/acme/app.git/info/refs", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("dumb info/refs: %d", resp.StatusCode)
	}

	// Expired and unknown tokens: 401.
	expired := e.tokenTTL(-time.Minute, "acme/*")
	for _, bad := range []string{expired, "ybp_" + strings.Repeat("A", 43), "garbage"} {
		resp, _ := e.do("GET", "/t/"+bad+"/git/test/acme/app/info/refs?service=git-upload-pack", nil, nil)
		if resp.StatusCode != 401 {
			t.Fatalf("token %q: %d", bad[:8], resp.StatusCode)
		}
	}
	if _, err := clientGit(t, 2, "", "ls-remote", e.basicURL(expired, "acme/app")); err == nil {
		t.Fatal("expired token worked with git")
	}
	if e.metric("yproxy_git_dead_token_requests_total", nil) == 0 {
		t.Fatal("dead token metric not counted")
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestCredentialsNotInArgv checks FR-93: upstream gets the token, but it is
// never in a command line, the mirror config or the remote URL.
func TestCredentialsNotInArgv(t *testing.T) {
	up := newUpstream(t)
	up.newRepo("acme", "secret")
	secret := "ghp_TopSecretUpstreamToken1234567890"
	up.requireAuth = basicHeader(secret)
	up.secrets = []string{secret, b64("x-access-token:" + secret)}
	f := filepath.Join(t.TempDir(), "gh_token")
	if err := os.WriteFile(f, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, up, envOpts{extraRemote: "      credentials: { token: { file: " + f + " } }"})
	tok := e.token("acme/*")

	mustClient(t, 2, "", "clone", "--quiet", e.url(tok, "acme/secret"), filepath.Join(t.TempDir(), "c"))
	dir := t.TempDir()
	mustGit(t, dir, "init", "--quiet")
	mustClient(t, 0, dir, "fetch", "--quiet", e.url(tok, "acme/secret"), mustGit(t, filepath.Join(up.root, "acme", "secret.git"), "rev-parse", "refs/pull/1/head"))
	if _, err := e.mgr.Refresh(t.Context(), "test", "acme", "secret"); err != nil {
		t.Fatal(err)
	}

	if !up.sawAuth.Load() {
		t.Fatal("upstream never received the credential")
	}
	if v := up.argvLeak.Load(); v != nil {
		t.Fatalf("credential visible in a process command line: %s", v)
	}
	for _, args := range e.execLog() {
		for _, s := range up.secrets {
			if strings.Contains(strings.Join(args, " "), s) {
				t.Fatalf("credential in argv: %v", args)
			}
		}
	}
	mi, _ := e.mgr.mirror("test", "acme", "secret")
	err := filepath.Walk(mi.dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 1<<20 {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, s := range up.secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("credential stored in %s", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A wrong credential's error message is redacted.
	up.authFn.Store(func(*http.Request) bool { return false })
	_, err = e.mgr.Refresh(t.Context(), "test", "acme", "secret")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("refresh with rejected credential: %v", err)
	}
}

// TestUpstreamDown checks FR-87 and acceptance 11: mirrored repos keep
// working while upstream is unreachable.
func TestUpstreamDown(t *testing.T) {
	up := newUpstream(t)
	up.newRepo("acme", "app")
	up.newRepo("acme", "never-mirrored")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/*")
	u := e.url(tok, "acme/app")
	mustClient(t, 2, "", "clone", "--quiet", u, filepath.Join(t.TempDir(), "c"))

	for _, mode := range []int32{1, 2} { // hanging, then failing upstream
		up.down.Store(mode)
		time.Sleep(250 * time.Millisecond)
		start := time.Now()
		for _, proto := range []int{0, 2} {
			mustClient(t, proto, "", "clone", "--quiet", u, filepath.Join(t.TempDir(), "c"))
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("stale clones took %s", d)
		}
	}
	if e.metric("yproxy_git_stale_served_total", nil) == 0 {
		t.Fatal("stale serves not counted")
	}
	details, _ := json.Marshal(e.mgr.ReadyDetails())
	if !strings.Contains(string(details), `"stale":["acme/app"]`) {
		t.Fatalf("readyz details: %s", details)
	}
	// A repo that was never mirrored can't be served: 502, not a hang.
	if _, err := clientGit(t, 2, "", "ls-remote", e.url(tok, "acme/never-mirrored")); err == nil {
		t.Fatal("unmirrored repo served while upstream is down")
	}

	up.down.Store(0)
	time.Sleep(250 * time.Millisecond)
	mustClient(t, 2, "", "ls-remote", u)
	if strings.Contains(fmt.Sprint(e.mgr.ReadyDetails()), "acme/app") {
		t.Fatal("still stale after upstream recovered")
	}
}

// TestSubmodule clones a superproject whose submodule URL points at the
// upstream host, rewritten to the proxy with insteadOf (requirements 10.3).
func TestSubmodule(t *testing.T) {
	up := newUpstream(t)
	up.newRepo("acme", "sub")
	super := up.newRepo("acme", "super")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/*")

	// The submodule URL uses the SSH form, like many real .gitmodules.
	mustGit(t, super.work, "-c", "protocol.file.allow=always", "submodule", "add", "--quiet", filepath.Join(up.root, "acme", "sub.git"), "sub")
	mustGit(t, super.work, "config", "--file", ".gitmodules", "submodule.sub.url", "git@github.example:acme/sub.git")
	super.commit("add submodule")
	super.push("main")

	proxyBase := e.proxy.URL + "/t/" + tok + "/git/test/"
	for _, proto := range []int{0, 2} {
		dir := filepath.Join(t.TempDir(), "c")
		mustClient(t, proto, "",
			"-c", "url."+proxyBase+".insteadOf=https://github.example/",
			"-c", "url."+proxyBase+".insteadOf=git@github.example:",
			"-c", "url."+proxyBase+".insteadOf=ssh://git@github.example/",
			"clone", "--quiet", "--recurse-submodules", "https://github.example/acme/super.git", dir)
		if _, err := os.Stat(filepath.Join(dir, "sub", "README")); err != nil {
			t.Fatalf("v%d: submodule not checked out: %v", proto, err)
		}
		// BitBake's protocol=ssh URL form.
		out := mustClient(t, proto, "", "-c", "url."+proxyBase+".insteadOf=ssh://git@github.example/",
			"ls-remote", "ssh://git@github.example/acme/super.git", "refs/heads/main")
		if !strings.HasSuffix(out, "refs/heads/main") {
			t.Fatalf("v%d: ssh:// insteadOf: %q", proto, out)
		}
	}
}

// TestGzipAndPaths sends a gzip-compressed v2 ls-refs request by hand.
func TestGzipAndPaths(t *testing.T) {
	up := newUpstream(t)
	r := up.newRepo("acme", "app")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/*")
	if resp, _ := e.do("GET", "/t/"+tok+"/git/test/acme/app/info/refs?service=git-upload-pack", map[string]string{"Git-Protocol": "version=2"}, nil); resp.StatusCode != 200 {
		t.Fatalf("info/refs: %d", resp.StatusCode)
	}
	var raw bytes.Buffer
	raw.WriteString("0014command=ls-refs\n0001")
	raw.Write(pktLine("ref-prefix refs/heads/\n"))
	raw.WriteString("0000")
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(raw.Bytes())
	zw.Close()
	resp, body := e.do("POST", "/t/"+tok+"/git/test/acme/app.git/git-upload-pack", map[string]string{
		"Content-Type": "application/x-git-upload-pack-request", "Content-Encoding": "gzip", "Git-Protocol": "version=2",
	}, &gz)
	if resp.StatusCode != 200 || !strings.Contains(body, mustGit(t, r.bare, "rev-parse", "main")+" refs/heads/main") || strings.Contains(body, "refs/tags") {
		t.Fatalf("ls-refs: %d %q", resp.StatusCode, body)
	}
	resp, _ = e.do("POST", "/t/"+tok+"/git/test/acme/app.git/git-upload-pack", map[string]string{"Content-Type": "text/plain"}, strings.NewReader("x"))
	if resp.StatusCode != 415 {
		t.Fatalf("wrong content type: %d", resp.StatusCode)
	}
}

// TestAdminAPI covers listing, forced refresh / pre-seeding and removal
// (FR-86, FR-92) and token creation with a git scope through the API.
func TestAdminAPI(t *testing.T) {
	up := newUpstream(t)
	r := up.newRepo("acme", "app")
	e := newEnv(t, up, envOpts{})

	resp, _ := e.adminDo("GET", "/api/v1/repos", "wrong")
	if resp.StatusCode != 401 {
		t.Fatalf("list without key: %d", resp.StatusCode)
	}
	// Pre-seed through refresh.
	resp, body := e.adminDo("POST", "/api/v1/repos/test/acme/app/refresh", e.adminKey)
	if resp.StatusCode != 200 || !strings.Contains(body, `"repo":"acme/app"`) {
		t.Fatalf("seed: %d %s", resp.StatusCode, body)
	}
	if resp, _ = e.adminDo("POST", "/api/v1/repos/test/evil/app/refresh", e.adminKey); resp.StatusCode != 404 {
		t.Fatalf("refresh outside allowlist: %d", resp.StatusCode)
	}
	// A forced refresh fetches immediately, even within ls_remote_cache.
	r.write("x", "y")
	sha := r.commit("new")
	r.push("main")
	if resp, body = e.adminDo("POST", "/api/v1/git/test/acme/app/refresh", e.adminKey); resp.StatusCode != 200 {
		t.Fatalf("refresh: %d %s", resp.StatusCode, body)
	}
	mi, _ := e.mgr.mirror("test", "acme", "app")
	if got := mustGit(t, "", "--git-dir="+mi.dir, "rev-parse", "main"); got != sha {
		t.Fatalf("mirror main = %s, want %s", got, sha)
	}

	resp, body = e.adminDo("GET", "/api/v1/repos", e.adminKey)
	var list struct {
		Repos   []Status     `json:"repos"`
		Remotes []remoteInfo `json:"remotes"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil || resp.StatusCode != 200 {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if len(list.Repos) != 1 || list.Repos[0].SizeBytes == 0 || list.Repos[0].LastFetch == nil ||
		list.Repos[0].CloneURL != "http://proxy.example/git/test/acme/app.git" {
		t.Fatalf("repos: %+v", list.Repos)
	}
	if len(list.Remotes) != 1 || list.Remotes[0].ProxyURL != "http://proxy.example/git/test/" || list.Remotes[0].Credentials != "none" {
		t.Fatalf("remotes: %+v", list.Remotes)
	}
	if e.metric("yproxy_git_mirrors", map[string]string{"remote": "test"}) != 1 || e.metric("yproxy_git_storage_bytes", nil) == 0 {
		t.Fatal("mirror gauges")
	}

	// Token creation through the API with a git scope, then a clone (FR-20, FR-90).
	req, _ := http.NewRequest("POST", e.admin.URL+"/api/v1/tokens",
		strings.NewReader(`{"git":[{"remote":"test","repos":["acme/*"]}],"ttl":"1h"}`))
	req.Header.Set("Authorization", "Bearer "+e.adminKey)
	tresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		Token    string            `json:"token"`
		Examples map[string]string `json:"examples"`
	}
	json.NewDecoder(tresp.Body).Decode(&created)
	tresp.Body.Close()
	if tresp.StatusCode != 201 || !strings.Contains(created.Examples["git_insteadof"], `/git/test/".insteadOf`) {
		t.Fatalf("create token: %d %+v", tresp.StatusCode, created)
	}
	mustClient(t, 2, "", "clone", "--quiet", e.basicURL(created.Token, "acme/app"), filepath.Join(t.TempDir(), "c"))
	if _, err := clientGit(t, 2, "", "ls-remote", e.basicURL(created.Token, "solo/one")); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("token scoped to acme/* read solo/one: %v", err)
	}

	// Remove.
	if resp, _ = e.adminDo("DELETE", "/api/v1/repos/test/acme/app", e.adminKey); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if _, err := os.Stat(mi.dir); !os.IsNotExist(err) {
		t.Fatal("mirror directory still exists")
	}
	if resp, _ = e.adminDo("DELETE", "/api/v1/repos/test/acme/app", e.adminKey); resp.StatusCode != 404 {
		t.Fatalf("second delete: %d", resp.StatusCode)
	}
	// And it comes back on the next request.
	mustClient(t, 2, "", "ls-remote", e.basicURL(created.Token, "acme/app"))
}

// TestEvictionAndRestart checks FR-89 and that mirrors survive a restart.
func TestEvictionAndRestart(t *testing.T) {
	up := newUpstream(t)
	up.newRepo("acme", "a")
	up.newRepo("acme", "b")
	up.newRepo("acme", "c")
	e := newEnv(t, up, envOpts{})
	tok := e.token("acme/*")
	for _, n := range []string{"a", "b", "c"} {
		mustClient(t, 2, "", "ls-remote", e.url(tok, "acme/"+n))
	}
	// A restarted manager finds the mirrors on disk.
	m2, err := New(t.Context(), e.cfg.Git, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m2.statuses()); n != 3 {
		t.Fatalf("after restart: %d mirrors", n)
	}

	// "a" unused for longer than evict_after; then the size limit evicts
	// the least recently used of the rest ("b").
	ma, _ := e.mgr.mirror("test", "acme", "a")
	mb, _ := e.mgr.mirror("test", "acme", "b")
	ma.mu.Lock()
	ma.meta.LastAccess = time.Now().Add(-100 * 24 * time.Hour)
	ma.mu.Unlock()
	mb.mu.Lock()
	mb.meta.LastAccess = time.Now().Add(-time.Hour)
	size := mb.meta.SizeBytes
	mb.mu.Unlock()
	e.cfg.Git.MaxSize = config.ByteSize(size + size/2)
	e.mgr.Maintain(t.Context())
	var left []string
	for _, st := range e.mgr.statuses() {
		left = append(left, st.Repo)
	}
	if strings.Join(left, ",") != "acme/c" {
		t.Fatalf("after eviction: %v", left)
	}
	if e.metric("yproxy_git_evictions_total", map[string]string{"reason": "unused"}) != 1 ||
		e.metric("yproxy_git_evictions_total", map[string]string{"reason": "size"}) != 1 {
		t.Fatal("eviction metrics")
	}
}
