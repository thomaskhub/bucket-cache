package s3proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

// fakeS3 is a minimal path-style S3 server: enough of GetObject, HeadObject
// and HeadBucket to exercise the real SDK client.
type fakeS3 struct {
	bucket  string
	objects map[string][]byte
	big     int64 // size of the generated object "big.bin"
	delay   time.Duration
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if parts[0] != f.bucket {
		s3Error(w, r, 404, "NoSuchBucket")
		return
	}
	if len(parts) == 1 || parts[1] == "" { // HeadBucket
		w.WriteHeader(200)
		return
	}
	key := parts[1]
	if strings.HasPrefix(key, "slow/") {
		time.Sleep(f.delay)
	}
	if strings.HasPrefix(key, "denied/") {
		s3Error(w, r, 403, "AccessDenied")
		return
	}
	if key == "big.bin" {
		w.Header().Set("Content-Length", strconv.FormatInt(f.big, 10))
		w.Header().Set("ETag", `"big"`)
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			io.CopyN(w, zeroReader{}, f.big)
		}
		return
	}
	data, ok := f.objects[key]
	if !ok {
		s3Error(w, r, 404, "NoSuchKey")
		return
	}
	etag := fmt.Sprintf(`"%x"`, sha256.Sum256(data))
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(304)
		return
	}
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Content-Type", "application/zstd")
	h.Set("Last-Modified", time.Unix(1_700_000_000, 0).UTC().Format(http.TimeFormat))
	if rg := r.Header.Get("Range"); rg != "" {
		var a, b int
		if _, err := fmt.Sscanf(rg, "bytes=%d-%d", &a, &b); err != nil || a >= len(data) {
			s3Error(w, r, 416, "InvalidRange")
			return
		}
		if b >= len(data) {
			b = len(data) - 1
		}
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", a, b, len(data)))
		h.Set("Content-Length", strconv.Itoa(b-a+1))
		w.WriteHeader(206)
		if r.Method == http.MethodGet {
			w.Write(data[a : b+1])
		}
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(200)
	if r.Method == http.MethodGet {
		w.Write(data)
	}
}

func s3Error(w http.ResponseWriter, r *http.Request, code int, s3code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(code)
	if r.Method != http.MethodHead {
		fmt.Fprintf(w, `<?xml version="1.0"?><Error><Code>%s</Code><Message>x</Message><BucketName>secret-bucket-name</BucketName></Error>`, s3code)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

type env struct {
	t       *testing.T
	proxy   *httptest.Server
	st      *store.Store
	authn   *auth.Authenticator
	handler *Handler
}

func newEnv(t *testing.T, fake *fakeS3) *env {
	t.Helper()
	backend := httptest.NewServer(fake)
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := writeFile(p, v); err != nil {
			t.Fatal(err)
		}
		return p
	}
	yml := fmt.Sprintf(`
buckets:
  - alias: sstate
    provider: generic
    endpoint: %s
    bucket: %s
    credentials:
      access_key_id: { file: %s }
      secret_access_key: { file: %s }
    timeouts: { first_byte: 300ms }
  - alias: other
    provider: generic
    endpoint: %s
    bucket: %s
    credentials:
      access_key_id: { file: %s }
      secret_access_key: { file: %s }
`, backend.URL, fake.bucket, write("ak", "AK"), write("sk", "SK"), backend.URL, fake.bucket, write("ak2", "AK"), write("sk2", "SK"))
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
	authn := auth.New(st, log, "", 5*time.Second)
	backends := map[string]Backend{}
	for _, b := range cfg.Buckets {
		backends[b.Alias] = NewS3Backend(b)
	}
	h := NewHandler(backends, authn, log, prometheus.NewRegistry(), false)
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.Match(r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	proxy := httptest.NewServer(mux)
	t.Cleanup(proxy.Close)
	return &env{t: t, proxy: proxy, st: st, authn: authn, handler: h}
}

func (e *env) token(scope store.Scope, ttl time.Duration) (string, *store.Token) {
	v := auth.NewSecret(auth.TokenPrefix)
	now := time.Now()
	tok := &store.Token{ID: auth.NewID("tok_"), Hash: auth.Hash(v), Kind: "ci", Scope: scope,
		CreatedBy: "test", CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := e.st.CreateToken(context.Background(), tok); err != nil {
		e.t.Fatal(err)
	}
	return v, tok
}

func (e *env) do(method, path string, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.proxy.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	// Don't let the client clean the path: BitBake sends "//" as-is.
	req.URL.Opaque = path
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

var sstateObj = bytes.Repeat([]byte("sstate-data-"), 1000)

func TestObjectAccess(t *testing.T) {
	fake := &fakeS3{bucket: "yocto-sstate", objects: map[string][]byte{"aa/bb/sstate:zlib.tar.zst": sstateObj}, delay: time.Second}
	e := newEnv(t, fake)
	tok, _ := e.token(store.Scope{Buckets: []string{"sstate"}}, time.Hour)
	key := "/sstate/aa/bb/sstate:zlib.tar.zst"

	resp, body := e.do("GET", "/t/"+tok+key, nil)
	if resp.StatusCode != 200 || !bytes.Equal(body, sstateObj) {
		t.Fatalf("GET = %d, %d bytes", resp.StatusCode, len(body))
	}
	if resp.Header.Get("Content-Type") != "application/zstd" || resp.Header.Get("ETag") == "" || resp.Header.Get("Last-Modified") == "" {
		t.Errorf("headers not passed through: %v", resp.Header)
	}

	// Doubled slashes from BitBake's PATH substitution work without a redirect.
	resp, body = e.do("GET", "/t/"+tok+"//sstate//aa/bb/sstate:zlib.tar.zst", nil)
	if resp.StatusCode != 200 || len(body) != len(sstateObj) {
		t.Fatalf("GET with // = %d", resp.StatusCode)
	}

	resp, body = e.do("HEAD", "/t/"+tok+key, nil)
	if resp.StatusCode != 200 || len(body) != 0 || resp.Header.Get("Content-Length") != strconv.Itoa(len(sstateObj)) {
		t.Fatalf("HEAD = %d, len %s", resp.StatusCode, resp.Header.Get("Content-Length"))
	}

	resp, body = e.do("GET", "/t/"+tok+key, map[string]string{"Range": "bytes=0-9"})
	if resp.StatusCode != 206 || string(body) != "sstate-dat" || resp.Header.Get("Content-Range") == "" {
		t.Fatalf("Range = %d %q", resp.StatusCode, body)
	}
	resp, _ = e.do("GET", "/t/"+tok+key, map[string]string{"Range": "bytes=999999-"})
	if resp.StatusCode != 416 {
		t.Fatalf("bad range = %d, want 416", resp.StatusCode)
	}

	resp, _ = e.do("GET", "/t/"+tok+key, nil)
	etag := resp.Header.Get("ETag")
	resp, _ = e.do("GET", "/t/"+tok+key, map[string]string{"If-None-Match": etag})
	if resp.StatusCode != 304 {
		t.Fatalf("If-None-Match = %d, want 304", resp.StatusCode)
	}

	// Header forms of the token.
	resp, _ = e.do("GET", key, map[string]string{"Authorization": "Bearer " + tok})
	if resp.StatusCode != 200 {
		t.Fatalf("Bearer = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", e.proxy.URL+key, nil)
	req.SetBasicAuth("ci", tok)
	r2, err := http.DefaultClient.Do(req)
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("Basic = %v %v", r2.StatusCode, err)
	}
	r2.Body.Close()
}

func TestStatusCodes(t *testing.T) {
	fake := &fakeS3{bucket: "yocto-sstate", objects: map[string][]byte{"k": []byte("x")}, delay: time.Second}
	e := newEnv(t, fake)
	tok, _ := e.token(store.Scope{Buckets: []string{"sstate"}}, time.Hour)
	dead, deadTok := e.token(store.Scope{Buckets: []string{"sstate"}}, time.Hour)
	e.st.RevokeToken(context.Background(), deadTok.ID, time.Now())

	cases := []struct {
		name, method, path string
		hdr                map[string]string
		want               int
	}{
		{"missing object", "GET", "/t/" + tok + "/sstate/nope", nil, 404},
		{"missing object HEAD", "HEAD", "/t/" + tok + "/sstate/nope", nil, 404},
		{"no credentials", "GET", "/sstate/k", nil, 401},
		{"unknown token", "GET", "/t/" + auth.NewSecret(auth.TokenPrefix) + "/sstate/k", nil, 401},
		{"revoked token", "GET", "/t/" + dead + "/sstate/k", nil, 401},
		{"bucket outside scope", "GET", "/t/" + tok + "/other/k", nil, 403},
		{"unknown bucket after auth", "GET", "/t/" + tok + "/nobucket/k", nil, 404},
		{"traversal", "GET", "/t/" + tok + "/sstate/a/../k", nil, 400},
		{"backend denies", "GET", "/t/" + tok + "/sstate/denied/k", nil, 502},
		{"backend slow", "GET", "/t/" + tok + "/sstate/slow/k", nil, 504},
		{"wrong method", "PUT", "/t/" + tok + "/sstate/k", nil, 405},
	}
	for _, c := range cases {
		resp, body := e.do(c.method, c.path, c.hdr)
		if resp.StatusCode != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, resp.StatusCode, c.want, body)
		}
		if resp.StatusCode == 401 && resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: 401 without WWW-Authenticate challenge", c.name)
		}
		if bytes.Contains(body, []byte("secret-bucket-name")) {
			t.Errorf("%s: backend error body leaked to client", c.name)
		}
	}
}

func TestScopePrefix(t *testing.T) {
	fake := &fakeS3{bucket: "yocto-sstate", objects: map[string][]byte{"kirkstone/a": []byte("1"), "scarthgap/a": []byte("2")}}
	e := newEnv(t, fake)
	tok, _ := e.token(store.Scope{Buckets: []string{"sstate"}, Prefixes: []string{"kirkstone/"}}, time.Hour)
	if resp, _ := e.do("GET", "/t/"+tok+"/sstate/kirkstone/a", nil); resp.StatusCode != 200 {
		t.Errorf("allowed prefix = %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/t/"+tok+"/sstate/scarthgap/a", nil); resp.StatusCode != 403 {
		t.Errorf("other prefix = %d, want 403", resp.StatusCode)
	}
}

func TestUnknownTokensRateLimitedButDeadTokensNot(t *testing.T) {
	fake := &fakeS3{bucket: "yocto-sstate", objects: map[string][]byte{"k": []byte("x")}}
	e := newEnv(t, fake)
	good, _ := e.token(store.Scope{Buckets: []string{"sstate"}}, time.Hour)
	dead, deadTok := e.token(store.Scope{Buckets: []string{"sstate"}}, time.Hour)
	e.st.RevokeToken(context.Background(), deadTok.ID, time.Now())

	// Thousands of requests with a revoked token (a big build) never trip the limiter.
	for i := 0; i < 500; i++ {
		if resp, _ := e.do("HEAD", "/t/"+dead+"/sstate/k", nil); resp.StatusCode != 401 {
			t.Fatalf("dead token request %d = %d, want 401", i, resp.StatusCode)
		}
	}
	if resp, _ := e.do("GET", "/t/"+good+"/sstate/k", nil); resp.StatusCode != 200 {
		t.Fatalf("good token after dead-token flood = %d", resp.StatusCode)
	}
	// Guessing random tokens does.
	limited := false
	for i := 0; i < 400; i++ {
		resp, _ := e.do("HEAD", "/t/"+auth.NewSecret(auth.TokenPrefix)+"/sstate/k", nil)
		if resp.StatusCode == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("random-token guessing was never rate limited")
	}
}

func TestUsageRecorded(t *testing.T) {
	fake := &fakeS3{bucket: "yocto-sstate", objects: map[string][]byte{"k": []byte("hello")}}
	e := newEnv(t, fake)
	v, tok := e.token(store.Scope{Buckets: []string{"sstate"}}, time.Hour)
	e.do("GET", "/t/"+v+"/sstate/k", nil)
	e.do("HEAD", "/t/"+v+"/sstate/k", nil)
	if err := e.authn.FlushUsage(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := e.st.TokenByID(context.Background(), tok.ID)
	if got.Requests != 2 || got.Bytes != 5 {
		t.Fatalf("usage = %d requests, %d bytes", got.Requests, got.Bytes)
	}
}

func TestLargeObjectStreamsWithFlatMemory(t *testing.T) {
	const size = 512 << 20 // 512 MiB
	fake := &fakeS3{bucket: "yocto-sstate", big: size}
	e := newEnv(t, fake)
	tok, _ := e.token(store.Scope{Buckets: []string{"sstate"}}, time.Hour)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	resp, err := http.Get(e.proxy.URL + "/t/" + tok + "/sstate/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != size {
		t.Fatalf("streamed %d bytes, err %v", n, err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if grow := int64(after.HeapInuse) - int64(before.HeapInuse); grow > 64<<20 {
		t.Fatalf("heap grew by %d MiB while streaming %d MiB", grow>>20, size>>20)
	}
}
