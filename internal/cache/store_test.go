package cache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newStore(t *testing.T, dir string, mod func(*Config)) (*Store, *clock) {
	t.Helper()
	clk := &clock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	cfg := Config{Dir: dir, Alias: "sstate", MaxSize: 1 << 20, NegativeTTL: 30 * time.Second, IdleTimeout: 5 * time.Second, Now: clk.Now}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, clk
}

func fetchBytes(data []byte, calls *atomic.Int32) FetchFunc {
	return func(context.Context) (Meta, io.ReadCloser, error) {
		if calls != nil {
			calls.Add(1)
		}
		return Meta{Size: int64(len(data)), ETag: `"e"`, ContentType: "application/zstd"}, io.NopCloser(bytes.NewReader(data)), nil
	}
}

func put(t *testing.T, s *Store, key string, data []byte) {
	t.Helper()
	r, err := s.Get(context.Background(), key, fetchBytes(data, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read %d bytes, err %v", len(got), err)
	}
	waitFor(t, func() bool { _, ok := s.Lookup(key); return ok })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// files lists every file under dir, relative to it.
func files(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

func TestFillThenHitAndReload(t *testing.T) {
	dir := t.TempDir()
	s, _ := newStore(t, dir, nil)
	var calls atomic.Int32
	data := bytes.Repeat([]byte("x"), 300_000)
	r, err := s.Get(context.Background(), "aa/sstate:zlib.tgz", fetchBytes(data, &calls))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("content differs")
	}
	waitFor(t, func() bool { _, ok := s.Lookup("aa/sstate:zlib.tgz"); return ok })
	m, _ := s.Lookup("aa/sstate:zlib.tgz")
	if m.Size != int64(len(data)) || m.ETag != `"e"` || m.ContentType != "application/zstd" {
		t.Fatalf("meta = %+v", m)
	}
	// A second Get is served from disk without fetching.
	r, err = s.Get(context.Background(), "aa/sstate:zlib.tgz", fetchBytes(nil, &calls))
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(r)
	r.Close()
	if !bytes.Equal(got, data) || calls.Load() != 1 {
		t.Fatalf("second get: %d bytes, %d fetches", len(got), calls.Load())
	}

	// Restart: the index and size accounting come back from the sidecars.
	s.Close()
	s2, _ := newStore(t, dir, nil)
	if m2, ok := s2.Lookup("aa/sstate:zlib.tgz"); !ok || m2.Size != m.Size {
		t.Fatal("object lost on reload")
	}
	if st := s2.Stats(); st.Objects != 1 || st.Size != int64(len(data)) {
		t.Fatalf("stats after reload = %+v", st)
	}
}

func TestPathsAreHashed(t *testing.T) {
	dir := t.TempDir()
	s, _ := newStore(t, dir, nil)
	keys := []string{"../../../etc/passwd", "/abs/path", "a\\b", strings.Repeat("k", 2000), "sstate:x:y:z.tar.zst"}
	for _, k := range keys {
		put(t, s, k, []byte(k))
	}
	for _, f := range files(t, dir) {
		if strings.HasPrefix(f, "..") || strings.Contains(f, "passwd") || strings.Contains(f, "abs") {
			t.Errorf("key leaked into path: %s", f)
		}
		parts := strings.Split(f, string(filepath.Separator))
		if len(parts) != 3 || parts[0] != "objects" || len(parts[1]) != 2 {
			t.Errorf("unexpected layout: %s", f)
		}
		if name := parts[2]; len(name) < 64 || name[:2] != parts[1] {
			t.Errorf("file name is not a hash: %s", f)
		}
	}
	if s.hash("a") == s.hash("b") {
		t.Fatal("hash collision")
	}
	// The same key in another bucket hashes differently.
	other, _ := newStore(t, t.TempDir(), func(c *Config) { c.Alias = "downloads" })
	if s.hash("k") == other.hash("k") {
		t.Fatal("alias is not part of the hash")
	}
	if _, err := New(Config{Dir: dir, Alias: "../x", MaxSize: 1}); err == nil {
		t.Fatal("alias with a path accepted")
	}
}

func TestConcurrentGetsShareOneFetch(t *testing.T) {
	s, _ := newStore(t, t.TempDir(), nil)
	var calls atomic.Int32
	release := make(chan struct{})
	data := bytes.Repeat([]byte("0123456789"), 50_000)
	fetch := func(context.Context) (Meta, io.ReadCloser, error) {
		calls.Add(1)
		<-release
		return Meta{Size: int64(len(data))}, io.NopCloser(bytes.NewReader(data)), nil
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			r, err := s.Get(context.Background(), "k", fetch)
			if err != nil {
				errs <- err
				return
			}
			defer r.Close()
			got, err := io.ReadAll(r)
			if err != nil || !bytes.Equal(got, data) {
				errs <- fmt.Errorf("read %d bytes: %w", len(got), err)
			}
		})
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
}

// failingBody returns part of the object and then an error, like a backend
// connection that drops mid-transfer.
type failingBody struct {
	data []byte
	sent int
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.sent >= len(b.data)/2 {
		return 0, errors.New("connection reset")
	}
	n := copy(p[:min(len(p), len(b.data)/2-b.sent)], b.data[b.sent:])
	b.sent += n
	return n, nil
}
func (b *failingBody) Close() error { return nil }

// readFill reads key through a fill. A fill that fails quickly may report
// its error from Get rather than from Read.
func readFill(s *Store, key string, fetch FetchFunc) ([]byte, error) {
	r, err := s.Get(context.Background(), key, fetch)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func TestInterruptedFillIsNeverVisible(t *testing.T) {
	dir := t.TempDir()
	s, _ := newStore(t, dir, nil)
	data := bytes.Repeat([]byte("y"), 200_000)
	got, err := readFill(s, "k", func(context.Context) (Meta, io.ReadCloser, error) {
		return Meta{Size: int64(len(data))}, &failingBody{data: data}, nil
	})
	if err == nil || len(got) >= len(data) {
		t.Fatalf("reader got %d bytes and err %v, want an error before the end", len(got), err)
	}
	waitFor(t, func() bool { return s.Stats().Filling == 0 })
	if _, ok := s.Lookup("k"); ok {
		t.Fatal("partial object is visible")
	}
	if f := files(t, dir); len(f) != 0 {
		t.Fatalf("files left behind: %v", f)
	}
	// The next request fetches again.
	put(t, s, "k", data)
}

func TestShortBodyIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	s, _ := newStore(t, dir, nil)
	_, err := readFill(s, "k", func(context.Context) (Meta, io.ReadCloser, error) {
		return Meta{Size: 100}, io.NopCloser(strings.NewReader("only 20 bytes here..")), nil
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want unexpected EOF", err)
	}
	waitFor(t, func() bool { return s.Stats().Filling == 0 })
	if _, ok := s.Lookup("k"); ok || len(files(t, dir)) != 0 {
		t.Fatal("short object was cached")
	}
}

// slowBody hands out the object in small chunks with a delay.
type slowBody struct {
	r     io.Reader
	delay time.Duration
}

func (b *slowBody) Read(p []byte) (int, error) {
	time.Sleep(b.delay)
	return b.r.Read(p[:min(len(p), 4096)])
}
func (b *slowBody) Close() error { return nil }

func TestClientCancelFinishesFillInBackground(t *testing.T) {
	s, _ := newStore(t, t.TempDir(), nil)
	data := bytes.Repeat([]byte("z"), 64*4096)
	ctx, cancel := context.WithCancel(context.Background())
	r, err := s.Get(ctx, "k", func(context.Context) (Meta, io.ReadCloser, error) {
		return Meta{Size: int64(len(data))}, &slowBody{r: bytes.NewReader(data), delay: time.Millisecond}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := io.ReadAll(r); !errors.Is(err, context.Canceled) {
		t.Fatalf("read after cancel: %v", err)
	}
	r.Close()
	if _, ok := s.Lookup("k"); ok {
		t.Fatal("object visible before the fill finished")
	}
	waitFor(t, func() bool { _, ok := s.Lookup("k"); return ok })
	m, _ := s.Lookup("k")
	f, err := s.OpenData(m)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, _ := io.ReadAll(f)
	if !bytes.Equal(got, data) {
		t.Fatalf("cached %d bytes, want %d", len(got), len(data))
	}
}

func TestStartupCleansCrashLeftovers(t *testing.T) {
	dir := t.TempDir()
	s, _ := newStore(t, dir, nil)
	put(t, s, "good", []byte("good data"))
	put(t, s, "truncated", []byte("this object gets truncated"))
	put(t, s, "nodata", []byte("this one loses its data file"))
	mt, _ := s.Lookup("truncated")
	mn, _ := s.Lookup("nodata")
	s.Close()

	// What a kill mid-transfer or mid-commit can leave behind.
	os.WriteFile(filepath.Join(dir, "tmp", "fill-123"), []byte("partial"), 0o600)
	os.WriteFile(filepath.Join(dir, "tmp", "meta-123"), []byte("{"), 0o600)
	h := s.hash("orphan")
	os.MkdirAll(s.dirFor(h), 0o750)
	os.WriteFile(s.dataPath(h, h+"-0000.data"), []byte("renamed but no sidecar"), 0o600)
	os.Truncate(s.dataPath(s.hash("truncated"), mt.Data), 5)
	os.Remove(s.dataPath(s.hash("nodata"), mn.Data))
	hb := s.hash("garbage")
	os.MkdirAll(s.dirFor(hb), 0o750)
	os.WriteFile(s.metaPath(hb), []byte("not json"), 0o600)

	s2, _ := newStore(t, dir, nil)
	if _, ok := s2.Lookup("good"); !ok {
		t.Fatal("good object lost")
	}
	for _, k := range []string{"truncated", "nodata", "orphan", "garbage"} {
		if _, ok := s2.Lookup(k); ok {
			t.Errorf("%s is visible after restart", k)
		}
	}
	got := files(t, dir)
	if len(got) != 2 { // the good object's sidecar and data file
		t.Fatalf("files after restart: %v", got)
	}
	if st := s2.Stats(); st.Size != int64(len("good data")) || st.Objects != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestEvictionByWatermark(t *testing.T) {
	s, clk := newStore(t, t.TempDir(), func(c *Config) { c.MaxSize = 1000 })
	obj := bytes.Repeat([]byte("e"), 100)
	for i := range 9 {
		put(t, s, fmt.Sprint(i), obj)
		clk.Add(time.Second)
	}
	if s.Sweep() != 0 {
		t.Fatal("evicted below the high watermark")
	}
	s.Lookup("0") // 0 is now the most recently used
	clk.Add(time.Second)
	put(t, s, "9", obj) // 1000 bytes > 950 high watermark
	s.Sweep()
	waitFor(t, func() bool { return s.Stats().Size <= 850 })
	for k, want := range map[string]bool{"0": true, "1": false, "2": false, "3": true, "9": true} {
		if _, ok := s.Lookup(k); ok != want {
			t.Errorf("object %s cached = %v, want %v", k, ok, want)
		}
	}
	if st := s.Stats(); st.Evictions != 2 || st.Objects != 8 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestTooLargeIsUncacheable(t *testing.T) {
	s, _ := newStore(t, t.TempDir(), func(c *Config) { c.MaxSize = 10 })
	_, err := s.Get(context.Background(), "k", fetchBytes(make([]byte, 11), nil))
	if !errors.Is(err, ErrUncacheable) {
		t.Fatalf("err = %v", err)
	}
}

func TestNegativeCache(t *testing.T) {
	s, clk := newStore(t, t.TempDir(), nil)
	s.SetMissing("k")
	if !s.Missing("k") {
		t.Fatal("not negatively cached")
	}
	clk.Add(29 * time.Second)
	if !s.Missing("k") {
		t.Fatal("expired early")
	}
	clk.Add(2 * time.Second)
	if s.Missing("k") {
		t.Fatal("still missing after negative_ttl")
	}
	// A successful fill clears the entry.
	s.SetMissing("k")
	put(t, s, "k", []byte("now it exists"))
	if s.Missing("k") {
		t.Fatal("negative entry survived a fill")
	}

	off, _ := newStore(t, t.TempDir(), func(c *Config) { c.NegativeTTL = 0 })
	off.SetMissing("k")
	if off.Missing("k") {
		t.Fatal("negative_ttl 0 should disable the negative cache")
	}
}

func TestFreshnessAndValidated(t *testing.T) {
	s, clk := newStore(t, t.TempDir(), func(c *Config) { c.Revalidate, c.MaxAge = true, time.Hour })
	put(t, s, "k", []byte("v"))
	m, _ := s.Lookup("k")
	if !s.Fresh(m) {
		t.Fatal("new object not fresh")
	}
	clk.Add(2 * time.Hour)
	if s.Fresh(m) {
		t.Fatal("object fresh after max_age")
	}
	s.Validated(m)
	m, _ = s.Lookup("k")
	if !s.Fresh(m) {
		t.Fatal("not fresh after revalidation")
	}
	imm, clk2 := newStore(t, t.TempDir(), nil)
	put(t, imm, "k", []byte("v"))
	clk2.Add(1000 * time.Hour)
	if m, _ := imm.Lookup("k"); !imm.Fresh(m) {
		t.Fatal("immutable object went stale")
	}
}

func TestPurge(t *testing.T) {
	dir := t.TempDir()
	s, _ := newStore(t, dir, nil)
	for _, k := range []string{"kirkstone/a", "kirkstone/b", "scarthgap/a", "x"} {
		put(t, s, k, []byte(k))
	}
	s.SetMissing("kirkstone/missing")
	if n, b := s.Purge("", "kirkstone/"); n != 2 || b != int64(len("kirkstone/a")*2) {
		t.Fatalf("prefix purge = %d, %d", n, b)
	}
	if s.Missing("kirkstone/missing") {
		t.Error("negative entry not purged")
	}
	if n, _ := s.Purge("x", ""); n != 1 {
		t.Fatalf("key purge = %d", n)
	}
	if _, ok := s.Lookup("scarthgap/a"); !ok {
		t.Fatal("unrelated object purged")
	}
	if n, _ := s.Purge("", ""); n != 1 || len(files(t, dir)) != 0 {
		t.Fatalf("purge all = %d, files %v", n, files(t, dir))
	}

	// A fill that is running during a purge is not committed.
	release := make(chan struct{})
	r, err := s.Get(context.Background(), "late", func(context.Context) (Meta, io.ReadCloser, error) {
		return Meta{Size: 4}, io.NopCloser(io.MultiReader(strings.NewReader("ab"), readAfter(release, "cd"))), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Purge("", "")
	close(release)
	got, _ := io.ReadAll(r)
	r.Close()
	if string(got) != "abcd" {
		t.Fatalf("reader got %q", got)
	}
	waitFor(t, func() bool { return s.Stats().Filling == 0 })
	if _, ok := s.Lookup("late"); ok {
		t.Fatal("purged fill was committed")
	}
}

type waitReader struct {
	ch <-chan struct{}
	r  io.Reader
}

func (w waitReader) Read(p []byte) (int, error) {
	<-w.ch
	return w.r.Read(p)
}

func readAfter(ch <-chan struct{}, s string) io.Reader { return waitReader{ch, strings.NewReader(s)} }

func TestIdleTimeoutAbortsFill(t *testing.T) {
	s, _ := newStore(t, t.TempDir(), func(c *Config) { c.IdleTimeout = 50 * time.Millisecond })
	r, err := s.Get(context.Background(), "k", func(ctx context.Context) (Meta, io.ReadCloser, error) {
		return Meta{Size: 10}, io.NopCloser(ctxReader{ctx}), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("stalled fill did not fail")
	}
}

// ctxReader blocks until ctx ends, like a stalled backend body.
type ctxReader struct{ ctx context.Context }

func (c ctxReader) Read([]byte) (int, error) {
	<-c.ctx.Done()
	return 0, c.ctx.Err()
}
