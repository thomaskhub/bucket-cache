package s3proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/cache"
	"github.com/thomaskhub/bucket-cache/internal/metrics"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

// Handler serves GET and HEAD for /t/{token}/{bucket}/{key} and, with the
// token in an Authorization header, /{bucket}/{key} (FR-1, FR-2).
type Handler struct {
	backends map[string]Backend
	caches   map[string]*cache.Store // buckets in mode: cache
	reval    coalescer[revalResult]
	auth     *auth.Authenticator
	limiter  *auth.IPLimiter
	log      *slog.Logger
	access   bool

	requests  *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	bytes     *prometheus.CounterVec
	backendEr *prometheus.CounterVec
	authFail  *prometheus.CounterVec
	deadToken *prometheus.CounterVec

	warnMu   sync.Mutex
	lastWarn map[string]time.Time
}

// NewHandler returns the data-plane handler. backends is keyed by alias.
func NewHandler(backends map[string]Backend, a *auth.Authenticator, log *slog.Logger, reg prometheus.Registerer, accessLog bool) *Handler {
	h := &Handler{
		backends: backends, auth: a, log: log, access: accessLog,
		caches:   map[string]*cache.Store{},
		limiter:  auth.NewIPLimiter(20, 200),
		lastWarn: map[string]time.Time{},
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "s3",
			Name: "requests_total", Help: "Object requests by bucket, method and status code."}, []string{"bucket", "method", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: metrics.Namespace, Subsystem: "s3",
			Name: "request_duration_seconds", Help: "Time to first byte of object requests.",
			Buckets: []float64{.002, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}}, []string{"bucket", "method"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "s3",
			Name: "bytes_served_total", Help: "Object bytes sent to clients."}, []string{"bucket"}),
		backendEr: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "s3",
			Name: "backend_errors_total", Help: "Unexpected backend failures by bucket and kind."}, []string{"bucket", "kind"}),
		authFail: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "auth",
			Name: "failures_total", Help: "Rejected data-plane requests by reason."}, []string{"reason"}),
		deadToken: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: metrics.Namespace, Subsystem: "auth",
			Name: "dead_token_requests_total", Help: "Requests with an expired or revoked token, by token ID (FR-27)."}, []string{"token_id"}),
	}
	reg.MustRegister(h.requests, h.duration, h.bytes, h.backendEr, h.authFail, h.deadToken)
	return h
}

// Match reports whether the request path belongs to this handler, so the
// server can route it without http.ServeMux (which would answer the "//"
// paths BitBake produces with a redirect).
func (h *Handler) Match(p string) bool {
	segs := splitPath(p)
	if len(segs) == 0 {
		return false
	}
	if segs[0] == "t" {
		return len(segs) >= 2
	}
	_, ok := h.backends[segs[0]]
	return ok
}

// splitPath collapses repeated slashes and splits the path into segments.
func splitPath(p string) []string {
	parts := strings.Split(p, "/")
	out := parts[:0]
	for _, s := range parts {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func validKey(segs []string) bool {
	if len(segs) == 0 {
		return false
	}
	for _, s := range segs {
		if s == "." || s == ".." || strings.ContainsAny(s, "\x00\\") {
			return false
		}
	}
	return true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	segs := splitPath(r.URL.Path)
	var pathToken string
	if len(segs) >= 2 && segs[0] == "t" {
		pathToken, segs = segs[1], segs[2:]
	}

	tok, ok := h.authenticate(w, r, pathToken)
	if !ok {
		return
	}

	if len(segs) < 2 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	alias, keySegs := segs[0], segs[1:]
	backend, found := h.backends[alias]
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !validKey(keySegs) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	key := strings.Join(keySegs, "/")
	if !auth.AllowsBucket(tok.Scope, alias, key) {
		h.authFail.WithLabelValues("scope").Inc()
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var code int
	var n int64
	xcache := cache.Bypass
	if c := h.caches[alias]; c != nil {
		code, n, xcache = h.serveCached(w, r, backend, c, alias, key)
	} else {
		code, n = h.serveObject(w, r, backend, alias, key)
	}
	h.requests.WithLabelValues(alias, r.Method, strconv.Itoa(code)).Inc()
	h.bytes.WithLabelValues(alias).Add(float64(n))
	h.auth.RecordUsage(tok.ID, n)
	if h.access {
		h.log.Info("request", "token_id", tok.ID, "method", r.Method, "bucket", alias, "key", key,
			"status", code, "bytes", n, "cache", xcache, "duration_ms", time.Since(start).Milliseconds())
	}
}

// authenticate finds the token in the path, a Bearer header or Basic auth
// (password), and validates it. It writes the error response itself.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, pathToken string) (*store.Token, bool) {
	value := pathToken
	if value == "" {
		if v, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); found {
			value = strings.TrimSpace(v)
		} else if _, pw, found := r.BasicAuth(); found {
			value = pw
		}
	}
	challenge := func(msg string) {
		// git and curl only send credentials after a Basic challenge (FR-7).
		w.Header().Set("WWW-Authenticate", `Basic realm="yproxy"`)
		http.Error(w, msg, http.StatusUnauthorized)
	}
	if value == "" {
		h.authFail.WithLabelValues("missing").Inc()
		challenge("unauthorized")
		return nil, false
	}
	ip := clientIP(r)
	if h.limiter.Blocked(ip) {
		h.authFail.WithLabelValues("rate_limited").Inc()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "too many invalid tokens", http.StatusTooManyRequests)
		return nil, false
	}
	tok, err := h.auth.Token(r.Context(), value)
	switch {
	case err == nil:
		return tok, true
	case errors.Is(err, auth.ErrDead):
		// Known token: answer 401 without counting it as a guess (SEC-3).
		h.authFail.WithLabelValues("expired_or_revoked").Inc()
		h.deadToken.WithLabelValues(tok.ID).Inc()
		h.warnDead(tok.ID)
		challenge("token expired or revoked")
	case errors.Is(err, auth.ErrUnknown):
		h.authFail.WithLabelValues("unknown").Inc()
		h.limiter.Allow(ip)
		challenge("unauthorized")
	default:
		h.log.Error("token lookup failed", "error", err.Error())
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}
	return nil, false
}

// warnDead logs at most one warning per token per minute, so an expired
// token in a big build is visible without flooding the log (FR-27).
func (h *Handler) warnDead(id string) {
	h.warnMu.Lock()
	defer h.warnMu.Unlock()
	if time.Since(h.lastWarn[id]) < time.Minute {
		return
	}
	h.lastWarn[id] = time.Now()
	h.log.Warn("request with expired or revoked token; builds using it fall back to building from source", "token_id", id)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func conditions(r *http.Request) Conditions {
	c := Conditions{Range: r.Header.Get("Range"), IfNoneMatch: r.Header.Get("If-None-Match")}
	if v := r.Header.Get("If-Modified-Since"); v != "" {
		if t, err := http.ParseTime(v); err == nil {
			c.IfModifiedSince = &t
		}
	}
	return c
}

var copyBufPool = sync.Pool{New: func() any { b := make([]byte, 256<<10); return &b }}

// serveObject fetches from the backend and streams the response. It returns
// the status code sent and the number of body bytes written.
func (h *Handler) serveObject(w http.ResponseWriter, r *http.Request, b Backend, alias, key string) (int, int64) {
	start := time.Now()
	w.Header().Set("X-Cache", cache.Bypass) // FR-74
	c := conditions(r)
	var obj *Object
	var err error
	if r.Method == http.MethodHead {
		obj, err = b.Head(r.Context(), key, c)
	} else {
		obj, err = b.Get(r.Context(), key, c)
	}
	h.duration.WithLabelValues(alias, r.Method).Observe(time.Since(start).Seconds())
	if err != nil {
		return h.writeError(w, r, alias, err), 0
	}
	if obj.Body != nil {
		defer obj.Body.Close()
	}

	hd := w.Header()
	ct := obj.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	hd.Set("Content-Type", ct)
	hd.Set("Accept-Ranges", "bytes")
	if obj.ETag != "" {
		hd.Set("ETag", obj.ETag)
	}
	if obj.LastModified != nil {
		hd.Set("Last-Modified", obj.LastModified.UTC().Format(http.TimeFormat))
	}
	hd.Set("Content-Length", strconv.FormatInt(obj.Size, 10))
	code := http.StatusOK
	if obj.ContentRange != "" {
		hd.Set("Content-Range", obj.ContentRange)
		code = http.StatusPartialContent
	}
	w.WriteHeader(code)
	if r.Method == http.MethodHead || obj.Body == nil {
		return code, 0
	}
	buf := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(buf)
	n, err := io.CopyBuffer(w, obj.Body, *buf)
	if err != nil && !errors.Is(err, context.Canceled) {
		h.log.Debug("transfer interrupted", "bucket", alias, "key", key, "bytes", n, "error", err.Error())
	}
	return code, n
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, alias string, err error) int {
	switch {
	case errors.Is(err, ErrNotFound):
		// 404 lets BitBake fall back to the next mirror or a local build fast.
		http.Error(w, "not found", http.StatusNotFound)
		return http.StatusNotFound
	case errors.Is(err, ErrNotModified):
		w.WriteHeader(http.StatusNotModified)
		return http.StatusNotModified
	case errors.Is(err, ErrPrecondition):
		http.Error(w, "precondition failed", http.StatusPreconditionFailed)
		return http.StatusPreconditionFailed
	case errors.Is(err, ErrRangeUnsatisfied):
		http.Error(w, "range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return http.StatusRequestedRangeNotSatisfiable
	case errors.Is(err, context.Canceled) || r.Context().Err() != nil:
		return 499 // client went away; nothing to send
	case errors.Is(err, ErrTimeout):
		h.backendEr.WithLabelValues(alias, "timeout").Inc()
		h.log.Warn("backend timeout", "bucket", alias)
		http.Error(w, "backend timeout", http.StatusGatewayTimeout)
		return http.StatusGatewayTimeout
	default:
		h.backendEr.WithLabelValues(alias, "error").Inc()
		h.log.Warn("backend error", "bucket", alias, "error", err.Error())
		http.Error(w, "backend error", http.StatusBadGateway)
		return http.StatusBadGateway
	}
}
