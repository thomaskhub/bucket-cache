package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/cache"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/s3proxy"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

func newCacheAPIEnv(t *testing.T) (*env, *cache.Store) {
	t.Helper()
	dir := t.TempDir()
	sec := filepath.Join(dir, "s")
	os.WriteFile(sec, []byte("SECRET"), 0o600)
	yml := `
storage: { cache_root: ` + filepath.Join(dir, "cache") + ` }
buckets:
  - alias: sstate
    provider: generic
    endpoint: http://s3.lan
    bucket: real-bucket
    credentials: { access_key_id: { file: ` + sec + ` }, secret_access_key: { file: ` + sec + ` } }
    mode: cache
    cache: { max_size: 1MiB }
  - alias: downloads
    provider: generic
    endpoint: http://s3.lan
    bucket: real-dl
    credentials: { access_key_id: { file: ` + sec + ` }, secret_access_key: { file: ` + sec + ` } }
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
	log := slog.New(slog.DiscardHandler)
	authn := auth.New(st, log, adminKey, 5*time.Second)
	c, err := cache.New(cache.ConfigFor(cfg.Storage.CacheRoot, cfg.Buckets[0]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	backends := map[string]s3proxy.Backend{"sstate": fakeBackend{}, "downloads": fakeBackend{}}
	mux := http.NewServeMux()
	New(cfg, st, authn, backends, log).WithCaches(map[string]*cache.Store{"sstate": c}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, authn: authn}, c
}

func fill(t *testing.T, c *cache.Store, key string) {
	t.Helper()
	data := []byte("object " + key)
	r, err := c.Get(context.Background(), key, func(context.Context) (cache.Meta, io.ReadCloser, error) {
		return cache.Meta{Size: int64(len(data))}, io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r)
	r.Close()
	for range 500 {
		if _, ok := c.Lookup(key); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s not cached", key)
}

func TestCacheStatsAndPurge(t *testing.T) {
	e, c := newCacheAPIEnv(t)
	for _, k := range []string{"kirkstone/a", "kirkstone/b", "scarthgap/a", "x"} {
		fill(t, c, k)
	}
	code, out := e.call("GET", "/api/v1/buckets/sstate/cache", adminKey, nil)
	if code != 200 || out["objects"] != float64(4) || out["max_size"] != float64(1<<20) || out["freshness"] != "immutable" {
		t.Fatalf("stats = %d %v", code, out["_raw"])
	}

	code, out = e.call("DELETE", "/api/v1/buckets/sstate/cache?prefix=kirkstone/", adminKey, nil)
	if code != 200 || out["removed"] != float64(2) {
		t.Fatalf("prefix purge = %d %v", code, out["_raw"])
	}
	code, out = e.call("DELETE", "/api/v1/buckets/sstate/cache?key=x", adminKey, nil)
	if code != 200 || out["removed"] != float64(1) {
		t.Fatalf("key purge = %d %v", code, out["_raw"])
	}
	if _, ok := c.Lookup("scarthgap/a"); !ok {
		t.Fatal("unrelated key purged")
	}
	code, out = e.call("DELETE", "/api/v1/buckets/sstate/cache", adminKey, nil)
	if code != 200 || out["removed"] != float64(1) || c.Stats().Objects != 0 {
		t.Fatalf("purge all = %d %v", code, out["_raw"])
	}

	if code, _ := e.call("DELETE", "/api/v1/buckets/sstate/cache?key=a&prefix=b", adminKey, nil); code != 400 {
		t.Errorf("key and prefix = %d, want 400", code)
	}
	if code, _ := e.call("GET", "/api/v1/buckets/downloads/cache", adminKey, nil); code != 409 {
		t.Errorf("pass-through bucket = %d, want 409", code)
	}
	if code, _ := e.call("GET", "/api/v1/buckets/nope/cache", adminKey, nil); code != 404 {
		t.Errorf("unknown bucket = %d, want 404", code)
	}

	// Admin role only.
	_, out = e.call("POST", "/api/v1/apikeys", adminKey, map[string]any{
		"name": "ci", "role": "token-issuer", "ceiling": map[string]any{"scope": map[string]any{"buckets": []string{"sstate"}}, "max_ttl": "8h"}})
	issuer := out["key"].(string)
	if code, _ := e.call("DELETE", "/api/v1/buckets/sstate/cache", issuer, nil); code != 403 {
		t.Errorf("issuer purge = %d, want 403", code)
	}
	if code, _ := e.call("GET", "/api/v1/buckets/sstate/cache", "", nil); code != 401 {
		t.Errorf("anonymous stats = %d, want 401", code)
	}
}
