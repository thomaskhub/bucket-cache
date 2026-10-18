package s3proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/cache"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

// ctrlS3 wraps fakeS3 with request counters, failure injection and objects
// that break or trickle mid-transfer.
type ctrlS3 struct {
	mu    sync.RWMutex
	fake  *fakeS3
	gets  atomic.Int64
	heads atomic.Int64
	fail  atomic.Bool
}

func (c *ctrlS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/"+c.fake.bucket+"/")
	if key == r.URL.Path || key == "" { // HeadBucket
		c.fake.ServeHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet {
		c.gets.Add(1)
	} else {
		c.heads.Add(1)
	}
	if c.fail.Load() {
		s3Error(w, r, 500, "InternalError")
		return
	}
	switch {
	case strings.HasPrefix(key, "broken/"):
		// Promise 100 kB, send half, then drop the connection.
		w.Header().Set("Content-Length", "100000")
		w.Header().Set("ETag", `"broken"`)
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			w.Write(make([]byte, 50000))
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}
		return
	case strings.HasPrefix(key, "trickle/"):
		w.Header().Set("Content-Length", strconv.Itoa(len(trickleObj)))
		w.Header().Set("ETag", `"trickle"`)
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			for i := 0; i < len(trickleObj); i += 16 << 10 {
				w.Write(trickleObj[i:min(i+16<<10, len(trickleObj))])
				w.(http.Flusher).Flush()
				time.Sleep(5 * time.Millisecond)
			}
		}
		return
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.fake.ServeHTTP(w, r)
}

func (c *ctrlS3) set(key string, data []byte) {
	c.mu.Lock()
	c.fake.objects[key] = data
	c.mu.Unlock()
}

var trickleObj = bytes.Repeat([]byte("trickle-"), 64<<10) // 512 KiB

type cacheEnv struct {
	*env
	ctrl   *ctrlS3
	stores map[string]*cache.Store
	root   string
	tok    string
}

// newCacheEnv sets up three cached buckets on one backend: "imm" (immutable),
// "reval" (revalidate, max_age 150ms, serve_stale) and "strict" (revalidate
// without serve_stale), plus "pass" in pass-through mode.
func newCacheEnv(t *testing.T, objects map[string][]byte) *cacheEnv {
	t.Helper()
	ctrl := &ctrlS3{fake: &fakeS3{bucket: "yocto-sstate", objects: objects, delay: 100 * time.Millisecond}}
	backend := httptest.NewServer(ctrl)
	t.Cleanup(backend.Close)

	dir := t.TempDir()
	sec := filepath.Join(dir, "sec")
	os.WriteFile(sec, []byte("K"), 0o600)
	bucket := func(alias, extra string) string {
		return fmt.Sprintf(`
  - alias: %s
    provider: generic
    endpoint: %s
    bucket: yocto-sstate
    credentials: { access_key_id: { file: %s }, secret_access_key: { file: %s } }
    timeouts: { first_byte: 1s, idle: 2s }
%s`, alias, backend.URL, sec, sec, extra)
	}
	yml := "storage: { cache_root: " + filepath.Join(dir, "cache") + " }\nbuckets:" +
		bucket("imm", "    mode: cache\n    cache: { max_size: 10MiB, negative_ttl: 300ms }\n") +
		bucket("reval", "    mode: cache\n    cache: { max_size: 10MiB, freshness: revalidate, max_age: 150ms, serve_stale: true }\n") +
		bucket("strict", "    mode: cache\n    cache: { max_size: 10MiB, freshness: revalidate, max_age: 150ms }\n") +
		bucket("pass", "")
	cfg, err := config.Parse([]byte(yml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), filepath.Join(dir, "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	log := slog.New(slog.DiscardHandler)
	authn := auth.New(st, log, "", 5*time.Second)
	backends := map[string]Backend{}
	for _, b := range cfg.Buckets {
		backends[b.Alias] = NewS3Backend(b)
	}
	reg := prometheus.NewRegistry()
	h := NewHandler(backends, authn, log, reg, false)
	stores, err := cache.OpenAll(cfg, log, reg)
	if err != nil {
		t.Fatal(err)
	}
	for a, c := range stores {
		h.SetCache(a, c)
	}
	proxy := httptest.NewServer(h)
	t.Cleanup(proxy.Close)
	t.Cleanup(func() { cache.CloseAll(stores) })
	e := &cacheEnv{env: &env{t: t, proxy: proxy, st: st, authn: authn, handler: h}, ctrl: ctrl, stores: stores, root: cfg.Storage.CacheRoot}
	e.tok, _ = e.token(store.Scope{Buckets: []string{"*"}}, time.Hour)
	return e
}

func (e *cacheEnv) get(method, bucket, key string, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	return e.do(method, "/t/"+e.tok+"/"+bucket+"/"+key, hdr)
}

func (e *cacheEnv) waitCached(bucket, key string) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := e.stores[bucket].Lookup(key); ok {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("%s/%s never got cached", bucket, key)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func xcache(r *http.Response) string { return r.Header.Get("X-Cache") }

func TestCacheMissThenHit(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{"aa/obj": sstateObj})
	resp, body := e.get("GET", "imm", "aa/obj", nil)
	if resp.StatusCode != 200 || xcache(resp) != "MISS" || !bytes.Equal(body, sstateObj) {
		t.Fatalf("first GET = %d %s, %d bytes", resp.StatusCode, xcache(resp), len(body))
	}
	e.waitCached("imm", "aa/obj")
	resp, body = e.get("GET", "imm", "aa/obj", nil)
	if resp.StatusCode != 200 || xcache(resp) != "HIT" || !bytes.Equal(body, sstateObj) {
		t.Fatalf("second GET = %d %s", resp.StatusCode, xcache(resp))
	}
	if resp.Header.Get("ETag") == "" || resp.Header.Get("Content-Type") != "application/zstd" ||
		resp.Header.Get("Last-Modified") == "" || resp.Header.Get("Content-Length") != strconv.Itoa(len(sstateObj)) {
		t.Errorf("hit headers = %v", resp.Header)
	}
	if n := e.ctrl.gets.Load(); n != 1 {
		t.Fatalf("backend GETs = %d, want 1", n)
	}
	if st := e.stores["imm"].Stats(); st.Hits != 1 || st.Misses != 1 || st.BytesSaved != int64(len(sstateObj)) {
		t.Errorf("stats = %+v", st)
	}
	// Pass-through buckets say so.
	if resp, _ := e.get("GET", "pass", "aa/obj", nil); xcache(resp) != "BYPASS" {
		t.Errorf("pass-through X-Cache = %q", xcache(resp))
	}
}

func TestCacheHeadHitWithoutBackend(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{"k": sstateObj, "other": []byte("x")})
	e.get("GET", "imm", "k", nil)
	e.waitCached("imm", "k")
	gets, heads := e.ctrl.gets.Load(), e.ctrl.heads.Load()
	for range 50 {
		resp, body := e.get("HEAD", "imm", "k", nil)
		if resp.StatusCode != 200 || xcache(resp) != "HIT" || len(body) != 0 || resp.Header.Get("Content-Length") != strconv.Itoa(len(sstateObj)) {
			t.Fatalf("HEAD = %d %s len %s", resp.StatusCode, xcache(resp), resp.Header.Get("Content-Length"))
		}
	}
	if e.ctrl.gets.Load() != gets || e.ctrl.heads.Load() != heads {
		t.Fatal("HEAD hits reached the backend")
	}
	// A HEAD miss asks the backend but doesn't download or cache the object.
	resp, _ := e.get("HEAD", "imm", "other", nil)
	if resp.StatusCode != 200 || xcache(resp) != "MISS" || e.ctrl.gets.Load() != gets {
		t.Fatalf("HEAD miss = %d %s, gets %d", resp.StatusCode, xcache(resp), e.ctrl.gets.Load())
	}
	if _, ok := e.stores["imm"].Lookup("other"); ok {
		t.Fatal("HEAD miss filled the cache")
	}
}

func TestCacheRangesAndConditionals(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{"k": sstateObj})
	// A Range request on a miss is answered from the fill.
	resp, body := e.get("GET", "imm", "k", map[string]string{"Range": "bytes=12-21"})
	if resp.StatusCode != 206 || string(body) != "sstate-dat" || xcache(resp) != "MISS" {
		t.Fatalf("range miss = %d %q %s", resp.StatusCode, body, xcache(resp))
	}
	e.waitCached("imm", "k")
	before := e.ctrl.gets.Load() + e.ctrl.heads.Load()
	m, _ := e.stores["imm"].Lookup("k")
	lm := m.LastModified.UTC().Format(http.TimeFormat)
	n := len(sstateObj)
	cases := []struct {
		name   string
		method string
		hdr    map[string]string
		code   int
		body   string
	}{
		{"range", "GET", map[string]string{"Range": "bytes=0-9"}, 206, "sstate-dat"},
		{"suffix range", "GET", map[string]string{"Range": "bytes=-5"}, 206, "data-"},
		{"open range", "GET", map[string]string{"Range": fmt.Sprintf("bytes=%d-", n-3)}, 206, "ta-"},
		{"bad range", "GET", map[string]string{"Range": "bytes=999999-"}, 416, ""},
		{"if-none-match", "GET", map[string]string{"If-None-Match": m.ETag}, 304, ""},
		{"if-none-match head", "HEAD", map[string]string{"If-None-Match": m.ETag}, 304, ""},
		{"if-none-match other", "GET", map[string]string{"If-None-Match": `"nope"`}, 200, string(sstateObj)},
		{"if-modified-since", "GET", map[string]string{"If-Modified-Since": lm}, 304, ""},
		{"if-match ok", "GET", map[string]string{"If-Match": m.ETag, "Range": "bytes=0-5"}, 206, "sstate"},
		{"if-match fails", "GET", map[string]string{"If-Match": `"nope"`}, 412, ""},
		{"if-unmodified-since fails", "GET", map[string]string{"If-Unmodified-Since": m.LastModified.Add(-time.Hour).UTC().Format(http.TimeFormat)}, 412, ""},
		{"if-range stale", "GET", map[string]string{"Range": "bytes=0-5", "If-Range": `"nope"`}, 200, string(sstateObj)},
	}
	for _, c := range cases {
		resp, body := e.get(c.method, "imm", "k", c.hdr)
		if resp.StatusCode != c.code || xcache(resp) != "HIT" {
			t.Errorf("%s: %d %s, want %d HIT", c.name, resp.StatusCode, xcache(resp), c.code)
			continue
		}
		if c.code != 416 && c.code != 412 && string(body) != c.body {
			t.Errorf("%s: body %q, want %q", c.name, body, c.body)
		}
	}
	if after := e.ctrl.gets.Load() + e.ctrl.heads.Load(); after != before {
		t.Fatalf("conditional and range hits made %d backend requests", after-before)
	}
}

func TestCacheConcurrentMissesCoalesced(t *testing.T) {
	big := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB
	e := newCacheEnv(t, map[string][]byte{"slow/obj": big})
	var wg sync.WaitGroup
	errs := make(chan string, 30)
	for range 30 {
		wg.Go(func() {
			resp, body := e.get("GET", "imm", "slow/obj", nil)
			if resp.StatusCode != 200 || !bytes.Equal(body, big) {
				errs <- fmt.Sprintf("%d, %d bytes", resp.StatusCode, len(body))
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n := e.ctrl.gets.Load(); n != 1 {
		t.Fatalf("backend GETs = %d, want 1", n)
	}
}

func TestCacheNegative(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{})
	resp, _ := e.get("GET", "imm", "missing", nil)
	if resp.StatusCode != 404 || xcache(resp) != "MISS" {
		t.Fatalf("first 404 = %d %s", resp.StatusCode, xcache(resp))
	}
	resp, _ = e.get("HEAD", "imm", "missing", nil)
	if resp.StatusCode != 404 || xcache(resp) != "HIT" || e.ctrl.gets.Load()+e.ctrl.heads.Load() != 1 {
		t.Fatalf("negative hit = %d %s, backend calls %d", resp.StatusCode, xcache(resp), e.ctrl.gets.Load()+e.ctrl.heads.Load())
	}
	// Once negative_ttl passes, an object uploaded meanwhile shows up.
	e.ctrl.set("missing", []byte("uploaded by another build"))
	time.Sleep(350 * time.Millisecond)
	resp, body := e.get("GET", "imm", "missing", nil)
	if resp.StatusCode != 200 || string(body) != "uploaded by another build" {
		t.Fatalf("after negative_ttl = %d %q", resp.StatusCode, body)
	}
}

func TestCacheImmutableVsRevalidate(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{"k": []byte("version 1")})
	for _, b := range []string{"imm", "reval"} {
		e.get("GET", b, "k", nil)
		e.waitCached(b, "k")
	}
	// Fresh within max_age: no backend request at all.
	heads := e.ctrl.heads.Load()
	if resp, _ := e.get("GET", "reval", "k", nil); xcache(resp) != "HIT" || e.ctrl.heads.Load() != heads {
		t.Fatalf("fresh hit = %s, heads %d", xcache(resp), e.ctrl.heads.Load()-heads)
	}
	// After max_age an unchanged object is revalidated with one conditional HEAD.
	time.Sleep(200 * time.Millisecond)
	if resp, body := e.get("GET", "reval", "k", nil); xcache(resp) != "HIT" || string(body) != "version 1" || e.ctrl.heads.Load() != heads+1 {
		t.Fatalf("revalidated hit = %s %q, heads %d", xcache(resp), body, e.ctrl.heads.Load()-heads)
	}
	if resp, _ := e.get("GET", "reval", "k", nil); xcache(resp) != "HIT" || e.ctrl.heads.Load() != heads+1 {
		t.Fatal("revalidation did not reset max_age")
	}

	e.ctrl.set("k", []byte("version 2"))
	time.Sleep(200 * time.Millisecond)
	resp, body := e.get("GET", "reval", "k", nil)
	if xcache(resp) != "MISS" || string(body) != "version 2" {
		t.Fatalf("changed object = %s %q", xcache(resp), body)
	}
	// immutable never asks the backend again.
	heads = e.ctrl.heads.Load()
	resp, body = e.get("GET", "imm", "k", nil)
	if xcache(resp) != "HIT" || string(body) != "version 1" || e.ctrl.heads.Load() != heads {
		t.Fatalf("immutable = %s %q", xcache(resp), body)
	}

	// Deleted upstream: dropped from the cache.
	e.ctrl.mu.Lock()
	delete(e.ctrl.fake.objects, "k")
	e.ctrl.mu.Unlock()
	time.Sleep(200 * time.Millisecond)
	e.waitCached("reval", "k")
	if resp, _ := e.get("HEAD", "reval", "k", nil); resp.StatusCode != 404 {
		t.Fatalf("deleted object = %d", resp.StatusCode)
	}
	if _, ok := e.stores["reval"].Lookup("k"); ok {
		t.Fatal("deleted object still cached")
	}
}

func TestCacheServeStale(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{"k": []byte("cached copy")})
	for _, b := range []string{"reval", "strict"} {
		e.get("GET", b, "k", nil)
		e.waitCached(b, "k")
	}
	e.ctrl.fail.Store(true)
	time.Sleep(200 * time.Millisecond)
	resp, body := e.get("GET", "reval", "k", nil)
	if resp.StatusCode != 200 || xcache(resp) != "STALE" || string(body) != "cached copy" {
		t.Fatalf("serve_stale = %d %s %q", resp.StatusCode, xcache(resp), body)
	}
	// Right after a failure the backend isn't asked again for every request.
	heads := e.ctrl.heads.Load()
	if resp, _ := e.get("HEAD", "reval", "k", nil); xcache(resp) != "STALE" || e.ctrl.heads.Load() != heads {
		t.Fatalf("second stale = %s, heads +%d", xcache(resp), e.ctrl.heads.Load()-heads)
	}
	if resp, _ := e.get("GET", "strict", "k", nil); resp.StatusCode != 502 {
		t.Fatalf("without serve_stale = %d, want 502", resp.StatusCode)
	}
	if st := e.stores["reval"].Stats(); st.Stale != 2 {
		t.Errorf("stale count = %d", st.Stale)
	}
}

func TestCacheBackendBreaksMidTransfer(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{})
	req, _ := http.NewRequest("GET", e.proxy.URL+"/t/"+e.tok+"/imm/broken/obj", nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		b, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr == nil && len(b) == 100000 {
			t.Fatal("client got a complete body from a broken transfer")
		}
	}
	c := e.stores["imm"]
	deadline := time.Now().Add(5 * time.Second)
	for c.Stats().Filling != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := c.Lookup("broken/obj"); ok {
		t.Fatal("partial object is cached")
	}
	e.assertNoFiles("imm")
	// The next request tries the backend again rather than serving garbage.
	before := e.ctrl.gets.Load()
	req, _ = http.NewRequest("GET", e.proxy.URL+"/t/"+e.tok+"/imm/broken/obj", nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if e.ctrl.gets.Load() == before {
		t.Fatal("broken object was not refetched")
	}
}

func TestCacheClientDisconnectStillFills(t *testing.T) {
	e := newCacheEnv(t, map[string][]byte{})
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", e.proxy.URL+"/t/"+e.tok+"/imm/trickle/obj", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 20000)); err != nil {
		t.Fatal(err)
	}
	cancel()
	resp.Body.Close()
	if _, ok := e.stores["imm"].Lookup("trickle/obj"); ok {
		t.Fatal("object visible before the fill finished")
	}
	e.waitCached("imm", "trickle/obj")
	resp2, body := e.get("GET", "imm", "trickle/obj", nil)
	if xcache(resp2) != "HIT" || !bytes.Equal(body, trickleObj) {
		t.Fatalf("after disconnect = %s, %d bytes", xcache(resp2), len(body))
	}
	if n := e.ctrl.gets.Load(); n != 1 {
		t.Fatalf("backend GETs = %d", n)
	}
}

// assertNoFiles checks that a bucket's cache directory holds no data,
// sidecar or temp files.
func (e *cacheEnv) assertNoFiles(alias string) {
	e.t.Helper()
	filepath.WalkDir(filepath.Join(e.root, alias), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			e.t.Errorf("file left in cache: %s", p)
		}
		return nil
	})
}
