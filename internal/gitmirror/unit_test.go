package gitmirror

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseGitPath(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want gitPath
	}{
		{"/git/github/acme/repo.git/info/refs", true, gitPath{remote: "github", owner: "acme", repo: "repo.git", rest: "info/refs"}},
		{"//git//github//Acme/Repo/git-upload-pack", true, gitPath{remote: "github", owner: "Acme", repo: "Repo", rest: "git-upload-pack"}},
		{"/t/ybp_x/git/github/acme/repo/info/refs", true, gitPath{token: "ybp_x", remote: "github", owner: "acme", repo: "repo", rest: "info/refs"}},
		{"/git/github/acme/repo", false, gitPath{}},
		{"/t/ybp_x/sstate/key", false, gitPath{}},
		{"/sstate/git/x", false, gitPath{}},
	}
	for _, c := range cases {
		got, ok := parseGitPath(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseGitPath(%q) = %+v, %v", c.in, got, ok)
		}
	}
	h := &Handler{}
	for p, want := range map[string]bool{"/git/x": true, "/t/tok/git/a/b/c/d": true, "/t/tok/sstate/k": false, "/gitx/a": false, "/t/tok": false} {
		if h.Match(p) != want {
			t.Errorf("Match(%q) != %v", p, want)
		}
	}
}

func TestNormalise(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"Acme", "Meta-Acme.GIT"}: "acme/meta-acme",
		{"yoctoproject", "poky"}:  "yoctoproject/poky",
		{"a", "b.c_d-e"}:          "a/b.c_d-e",
		{"..", "x"}:               "",
		{".hidden", "x"}:          "",
		{"a", ".git"}:             "",
		{"a", "x.lock"}:           "",
		{"a b", "x"}:              "",
		{"a", "x%2f"}:             "",
	} {
		o, r, ok := normalise(in[0], in[1])
		got := ""
		if ok {
			got = o + "/" + r
		}
		if got != want {
			t.Errorf("normalise(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScanRequest(t *testing.T) {
	sha1 := strings.Repeat("a", 40)
	sha2 := strings.Repeat("b", 40)
	var v0 bytes.Buffer
	v0.Write(pktLine("want " + sha1 + " multi_ack_detailed side-band-64k\n"))
	v0.Write(pktLine("want " + sha2 + "\n"))
	v0.Write(pktLine("want " + sha2 + "\n"))
	v0.WriteString("0000")
	v0.Write(pktLine("have " + sha1 + "\n"))
	v0.Write(pktLine("done\n"))
	u, err := scanRequest(&v0)
	if err != nil || len(u.wants) != 2 || !u.haves || u.operation() != "fetch" {
		t.Fatalf("v0: %+v %v", u, err)
	}
	var v2 bytes.Buffer
	v2.Write(pktLine("command=fetch\n"))
	v2.Write(pktLine("agent=git/2.43\n"))
	v2.WriteString("0001")
	v2.Write(pktLine("thin-pack\n"))
	v2.Write(pktLine("want " + sha1 + "\n"))
	v2.Write(pktLine("done\n"))
	v2.WriteString("0000")
	u, err = scanRequest(&v2)
	if err != nil || u.command != "fetch" || len(u.wants) != 1 || u.operation() != "clone" {
		t.Fatalf("v2: %+v %v", u, err)
	}
	u, _ = scanRequest(strings.NewReader("0014command=ls-refs\n0000"))
	if u.operation() != "ls-refs" {
		t.Fatalf("ls-refs: %+v", u)
	}
	u, err = scanRequest(strings.NewReader("zzzzgarbage"))
	if err != nil || len(u.wants) != 0 {
		t.Fatalf("garbage: %+v %v", u, err)
	}
}

func TestSpool(t *testing.T) {
	s := &spool{dir: t.TempDir(), memLimit: 10}
	s.Write([]byte("hello "))
	s.Write([]byte("world, this spills"))
	if s.f == nil {
		t.Fatal("expected spill to file")
	}
	r, _ := s.Reader()
	b := new(bytes.Buffer)
	b.ReadFrom(r)
	if b.String() != "hello world, this spills" {
		t.Fatalf("got %q", b)
	}
	name := s.f.Name()
	s.Close()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatal("temp file not removed")
	}
}

func TestCredEnv(t *testing.T) {
	env := credEnv("https://github.com/", "Basic abc")
	want := []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.https://github.com/.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic abc"}
	if strings.Join(env, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v", env)
	}
	if credEnv("https://x", "") != nil {
		t.Fatal("anonymous should add nothing")
	}
	if defaultAPIURL("https://github.com") != "https://api.github.com" || defaultAPIURL("https://ghe.corp/") != "https://ghe.corp/api/v3" {
		t.Fatal("defaultAPIURL")
	}
}

func verifyJWT(t *testing.T, pub *rsa.PublicKey, tok, appID string) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt %q", tok)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("bad signature: %v", err)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if string(hdr) != `{"alg":"RS256","typ":"JWT"}` {
		t.Fatalf("header %s", hdr)
	}
	var claims struct {
		Iat, Exp int64
		Iss      string
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if claims.Iss != appID || claims.Iat > now || claims.Exp <= now || claims.Exp-claims.Iat > 600 {
		t.Fatalf("claims %+v", claims)
	}
}

// TestGitHubApp mirrors a private repo with GitHub App credentials: JWT →
// installation token, refreshed before it expires (FR-80, FR-93).
func TestGitHubApp(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "app.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	up := newUpstream(t)
	up.newRepo("acme", "private")
	var issued atomic.Int32
	var current atomic.Value
	current.Store("")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/{owner}/{repo}/installation", func(w http.ResponseWriter, r *http.Request) {
		verifyJWT(t, &key.PublicKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "12345")
		if r.PathValue("owner") != "acme" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, `{"id": 777}`)
	})
	mux.HandleFunc("POST /api/v3/app/installations/777/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		verifyJWT(t, &key.PublicKey, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "12345")
		n := issued.Add(1)
		tok := fmt.Sprintf("ghs_installation_token_%d", n)
		current.Store(tok)
		// Expires within the refresh margin, so the next use refreshes it.
		exp := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"token": %q, "expires_at": %q}`, tok, exp)
	})
	up.api = mux
	// Upstream accepts only the latest installation token.
	up.authFn.Store(func(r *http.Request) bool {
		return r.Header.Get("Authorization") == basicHeader(current.Load().(string))
	})

	e := newEnv(t, up, envOpts{extraRemote: fmt.Sprintf("      credentials: { app_id: \"12345\", app_private_key: { file: %s } }", keyFile)})
	tok := e.token("acme/*")
	mustClient(t, 2, "", "clone", "--quiet", e.url(tok, "acme/private"), filepath.Join(t.TempDir(), "c"))
	before := issued.Load()
	if _, err := e.mgr.Refresh(t.Context(), "test", "acme", "private"); err != nil {
		t.Fatal(err)
	}
	if issued.Load() <= before {
		t.Fatal("installation token was not refreshed")
	}
	for _, args := range e.execLog() {
		if strings.Contains(strings.Join(args, " "), "ghs_") {
			t.Fatalf("installation token in argv: %v", args)
		}
	}
}
