package s3proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/cache"
)

// SetCache turns on the disk cache for a bucket in mode: cache. Call it
// before the handler serves requests.
func (h *Handler) SetCache(alias string, c *cache.Store) { h.caches[alias] = c }

// serveCached answers from the disk cache, filling it on a miss (FR-50..56).
// Range and conditional requests (If-None-Match, If-Modified-Since,
// If-Match, If-Unmodified-Since) are evaluated locally by http.ServeContent
// against the cached metadata. It returns the status, body bytes and the
// cache status for the access log.
func (h *Handler) serveCached(w http.ResponseWriter, r *http.Request, b Backend, c *cache.Store, alias, key string) (int, int64, string) {
	start := time.Now()
	if m, ok := c.Lookup(key); ok {
		status, serve := cache.Hit, true
		if !c.Fresh(m) {
			switch res, err := h.revalidate(r.Context(), b, c, m); {
			case res == revalFresh:
			case res == revalChanged:
				serve = false
			case res == revalGone:
				return h.cachedError(w, r, c, alias, key, ErrNotFound, start)
			case c.ServeStale():
				status = cache.Stale // FR-56
				h.log.Debug("serving stale object", "bucket", alias, "key", key, "error", err.Error())
			default:
				return h.cachedError(w, r, c, alias, key, err, start)
			}
		}
		if serve {
			if res, ok := h.serveHit(w, r, c, m, status, alias, start); ok {
				return res.code, res.n, status
			}
			// The data file was damaged or evicted; fetch it again.
		}
	}
	if c.Missing(key) {
		w.Header().Set("X-Cache", cache.Hit)
		h.duration.WithLabelValues(alias, r.Method).Observe(time.Since(start).Seconds())
		c.Record(cache.Hit, 0)
		http.Error(w, "not found", http.StatusNotFound)
		return http.StatusNotFound, 0, cache.Hit
	}

	if r.Method == http.MethodHead {
		// A HEAD miss never downloads the object (FR-8).
		obj, err := b.Head(r.Context(), key, Conditions{})
		if err != nil {
			return h.cachedError(w, r, c, alias, key, err, start)
		}
		m := metaOf(obj)
		h.duration.WithLabelValues(alias, r.Method).Observe(time.Since(start).Seconds())
		res := serveContent(w, r, m, cache.Miss, sizeOnly(m.Size))
		c.Record(cache.Miss, 0)
		return res.code, 0, cache.Miss
	}

	rd, err := c.Get(r.Context(), key, func(ctx context.Context) (cache.Meta, io.ReadCloser, error) {
		obj, err := b.Get(ctx, key, Conditions{})
		if err != nil {
			return cache.Meta{}, nil, err
		}
		return metaOf(obj), obj.Body, nil
	})
	if errors.Is(err, cache.ErrUncacheable) {
		c.Record(cache.Bypass, 0)
		code, n := h.serveObject(w, r, b, alias, key)
		return code, n, cache.Bypass
	}
	if err != nil {
		return h.cachedError(w, r, c, alias, key, err, start)
	}
	defer rd.Close()
	h.duration.WithLabelValues(alias, r.Method).Observe(time.Since(start).Seconds())
	res := serveContent(w, r, rd.Meta(), cache.Miss, rd)
	c.Record(cache.Miss, res.n)
	return res.code, res.n, cache.Miss
}

func metaOf(o *Object) cache.Meta {
	m := cache.Meta{Size: o.Size, ETag: o.ETag, ContentType: o.ContentType}
	if o.LastModified != nil {
		m.LastModified = *o.LastModified
	}
	return m
}

// serveHit serves a cached object. ok is false if its data file is gone.
func (h *Handler) serveHit(w http.ResponseWriter, r *http.Request, c *cache.Store, m cache.Meta, status, alias string, start time.Time) (result, bool) {
	var content io.ReadSeeker = sizeOnly(m.Size)
	if r.Method != http.MethodHead {
		f, err := c.OpenData(m)
		if err != nil {
			return result{}, false
		}
		defer f.Close()
		content = f // an *os.File lets net/http use sendfile
	}
	h.duration.WithLabelValues(alias, r.Method).Observe(time.Since(start).Seconds())
	res := serveContent(w, r, m, status, content)
	c.Record(status, res.n)
	return res, true
}

func (h *Handler) cachedError(w http.ResponseWriter, r *http.Request, c *cache.Store, alias, key string, err error, start time.Time) (int, int64, string) {
	if errors.Is(err, ErrNotFound) {
		c.SetMissing(key) // FR-55
	}
	h.duration.WithLabelValues(alias, r.Method).Observe(time.Since(start).Seconds())
	w.Header().Set("X-Cache", cache.Miss)
	c.Record(cache.Miss, 0)
	return h.writeError(w, r, alias, err), 0, cache.Miss
}

type result struct {
	code int
	n    int64
}

func serveContent(w http.ResponseWriter, r *http.Request, m cache.Meta, status string, content io.ReadSeeker) result {
	hd := w.Header()
	ct := m.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	hd.Set("Content-Type", ct)
	if m.ETag != "" {
		hd.Set("ETag", m.ETag)
	}
	hd.Set("X-Cache", status)
	cw := &countingWriter{ResponseWriter: w}
	http.ServeContent(cw, r, "", m.LastModified, content)
	if cw.code == 0 {
		cw.code = http.StatusOK
	}
	return result{cw.code, cw.n}
}

// sizeOnly is the content for HEAD responses: ServeContent needs the size
// (and seeks for ranges) but never reads the body of a HEAD.
type sizeOnly int64

func (s sizeOnly) Read([]byte) (int, error) { return 0, errors.New("no body for HEAD") }
func (s sizeOnly) Seek(offset int64, whence int) (int64, error) {
	if whence == io.SeekEnd {
		return int64(s) + offset, nil
	}
	return offset, nil
}

// countingWriter records the status and body bytes. It keeps ReadFrom so
// net/http can still use sendfile for cache hits.
type countingWriter struct {
	http.ResponseWriter
	code int
	n    int64
}

func (c *countingWriter) WriteHeader(code int) {
	if c.code == 0 {
		c.code = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}

func (c *countingWriter) ReadFrom(src io.Reader) (int64, error) {
	if c.code == 0 {
		c.code = http.StatusOK
	}
	if rf, ok := c.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(src)
		c.n += n
		return n, err
	}
	return io.Copy(struct{ io.Writer }{c}, src)
}

func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

type revalResult int

const (
	revalFresh revalResult = iota
	revalChanged
	revalGone
	revalFailed
)

// revalidate sends a conditional HEAD with the stored ETag once max_age has
// passed (FR-54). Concurrent revalidations of one key share a request, and
// the request isn't tied to one client so a disconnect doesn't fail the
// others. A changed object is dropped and fetched again by the caller's
// fill; a deleted one is dropped and negatively cached. After a failure the
// backend counts as down for a few seconds, so with serve_stale the next
// requests are answered at once instead of each waiting for a timeout.
func (h *Handler) revalidate(ctx context.Context, b Backend, c *cache.Store, m cache.Meta) (revalResult, error) {
	if c.ServeStale() && c.BackendDown() {
		return revalFailed, errBackendDown
	}
	return h.reval.do(c.Alias()+"\x00"+m.Key, func() (revalResult, error) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.RevalidateTimeout())
		defer cancel()
		obj, err := b.Head(ctx, m.Key, Conditions{IfNoneMatch: m.ETag})
		switch {
		case errors.Is(err, ErrNotModified) || (err == nil && sameObject(obj, m)):
			c.Validated(m)
			return revalFresh, nil
		case err == nil:
			c.Remove(m) // changed upstream: refetch
			return revalChanged, nil
		case errors.Is(err, ErrNotFound):
			c.Remove(m)
			c.SetMissing(m.Key)
			return revalGone, nil
		default:
			c.MarkBackendDown()
			return revalFailed, err
		}
	})
}

var errBackendDown = errors.New("backend failed recently")

func sameObject(o *Object, m cache.Meta) bool {
	if o.ETag != "" || m.ETag != "" {
		return o.ETag == m.ETag
	}
	return o.Size == m.Size && o.LastModified != nil && o.LastModified.Equal(m.LastModified)
}

// coalescer runs one call per key at a time and shares its result.
type coalescer[T any] struct {
	mu    sync.Mutex
	calls map[string]*call[T]
}

type call[T any] struct {
	done chan struct{}
	v    T
	err  error
}

func (g *coalescer[T]) do(key string, fn func() (T, error)) (T, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = map[string]*call[T]{}
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		<-c.done
		return c.v, c.err
	}
	c := &call[T]{done: make(chan struct{})}
	g.calls[key] = c
	g.mu.Unlock()
	c.v, c.err = fn()
	g.mu.Lock()
	delete(g.calls, key)
	g.mu.Unlock()
	close(c.done)
	return c.v, c.err
}
