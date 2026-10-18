package gitmirror

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

// maxRequestBody bounds a decompressed upload-pack request (wants and haves).
const maxRequestBody = 256 << 20

// Handler serves git smart HTTP, read-only (FR-81, FR-82):
//
//	/git/{remote}/{owner}/{repo}[.git]/info/refs?service=git-upload-pack
//	/git/{remote}/{owner}/{repo}[.git]/git-upload-pack
//	/t/{token}/git/...   (token in the path, for tools that can't send credentials)
type Handler struct {
	mgr     *Manager
	auth    *auth.Authenticator
	limiter *auth.IPLimiter
	log     *slog.Logger
	access  bool

	warnMu   sync.Mutex
	lastWarn map[string]time.Time
}

// NewHandler returns the git data-plane route.
func (m *Manager) NewHandler(a *auth.Authenticator, accessLog bool) *Handler {
	return &Handler{mgr: m, auth: a, limiter: auth.NewIPLimiter(20, 200), log: m.log, access: accessLog, lastWarn: map[string]time.Time{}}
}

// Match claims /git/... and /t/{token}/git/... . It must be registered
// before the object route, which also claims /t/... .
func (h *Handler) Match(p string) bool {
	segs := splitPath(p)
	switch {
	case len(segs) >= 1 && segs[0] == "git":
		return true
	case len(segs) >= 3 && segs[0] == "t" && segs[2] == "git":
		return true
	}
	return false
}

// splitPath collapses repeated slashes ("//" from BitBake's PATH
// substitution, without a redirect) and splits the path into segments.
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

type gitPath struct {
	token  string
	remote string
	owner  string // as sent; normalised later
	repo   string
	rest   string // "info/refs", "git-upload-pack", ...
}

func parseGitPath(p string) (gitPath, bool) {
	segs := splitPath(p)
	var gp gitPath
	switch {
	case len(segs) >= 3 && segs[0] == "t" && segs[2] == "git":
		gp.token, segs = segs[1], segs[3:]
	case len(segs) >= 1 && segs[0] == "git":
		segs = segs[1:]
	default:
		return gp, false
	}
	if len(segs) < 4 {
		return gp, false
	}
	gp.remote, gp.owner, gp.repo, gp.rest = segs[0], segs[1], segs[2], strings.Join(segs[3:], "/")
	return gp, true
}

// statusWriter records the status code and body bytes sent.
type statusWriter struct {
	http.ResponseWriter
	code  int
	bytes int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	start := time.Now()
	w := &statusWriter{ResponseWriter: rw}
	gp, ok := parseGitPath(r.URL.Path)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var advertise bool
	switch gp.rest {
	case "info/refs":
		switch r.URL.Query().Get("service") {
		case "git-upload-pack":
		case "git-receive-pack":
			h.rejectPush(w)
			return
		default:
			http.Error(w, "only git smart HTTP is supported", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		advertise = true
	case "git-upload-pack":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	case "git-receive-pack":
		h.rejectPush(w)
		return
	default:
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Credentials first: without them git always gets 401, never 404 (FR-7).
	tok, ok := h.authenticate(w, r, gp.token)
	if !ok {
		return
	}
	owner, repo, ok := normalise(gp.owner, gp.repo)
	if !ok || !h.mgr.Allowed(gp.remote, owner, repo) {
		// Outside the allowlist: 404, so the proxy never acts as an open mirror (FR-80).
		http.Error(w, "repository not found", http.StatusNotFound)
		return
	}
	if !auth.AllowsRepo(tok.Scope, gp.remote, owner+"/"+repo) {
		h.mgr.met.authFail.WithLabelValues("scope").Inc()
		http.Error(w, "token does not allow this repository", http.StatusForbidden)
		return
	}

	mi, release, err := h.mgr.open(gp.remote, owner, repo)
	if err != nil {
		http.Error(w, "repository not found", http.StatusNotFound)
		return
	}
	defer release()

	op := "advertise"
	if advertise {
		h.serveAdvertisement(w, r, mi)
	} else {
		op = h.serveUploadPack(w, r, mi)
	}
	code := w.code
	if code == 0 {
		code = 499 // client went away before anything was sent
	}
	h.mgr.met.requests.WithLabelValues(gp.remote, owner+"/"+repo, op, strconv.Itoa(code)).Inc()
	h.mgr.met.bytes.WithLabelValues(gp.remote).Add(float64(w.bytes))
	h.auth.RecordUsage(tok.ID, w.bytes)
	if h.access {
		h.log.Info("git request", "token_id", tok.ID, "remote", gp.remote, "repo", owner+"/"+repo, "operation", op,
			"status", code, "bytes", w.bytes, "duration_ms", time.Since(start).Milliseconds())
	}
}

func (h *Handler) rejectPush(w http.ResponseWriter) {
	h.mgr.met.requests.WithLabelValues("", "", "push", "403").Inc()
	http.Error(w, "this is a read-only mirror; push to the upstream repository instead", http.StatusForbidden)
}

func noCache(hd http.Header) {
	hd.Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	hd.Set("Pragma", "no-cache")
	hd.Set("Expires", "Fri, 01 Jan 1980 00:00:00 GMT")
}

// gitProtocolRe accepts the Git-Protocol header values git sends, such as
// "version=2"; anything else is dropped rather than passed to git.
var gitProtocolRe = regexp.MustCompile(`^[A-Za-z0-9=:._-]{1,256}$`)

func gitProtocol(r *http.Request) string {
	v := r.Header.Get("Git-Protocol")
	if !gitProtocolRe.MatchString(v) {
		return ""
	}
	return v
}

func isV2(proto string) bool {
	for _, kv := range strings.Split(proto, ":") {
		if kv == "version=2" {
			return true
		}
	}
	return false
}

// upstreamStatus maps a failed first clone to a status code: 404 when
// upstream says the repo doesn't exist (so BitBake moves on quickly), 504
// on timeout, else 502.
func upstreamStatus(err error) int {
	var ge *GitError
	if errors.As(err, &ge) {
		s := strings.ToLower(ge.Stderr)
		if strings.Contains(s, "not found") || strings.Contains(s, "error: 404") {
			return http.StatusNotFound
		}
	}
	if isTimeout(err) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

func upstreamError(w http.ResponseWriter, err error) {
	code := upstreamStatus(err)
	msg := "upstream repository unavailable"
	if code == http.StatusNotFound {
		msg = "repository not found upstream"
	}
	http.Error(w, msg, code)
}

// serveAdvertisement answers info/refs. Every clone and fetch over HTTP
// starts here (also with protocol v2, where the ref list follows in an
// ls-refs POST), so this is where freshness is checked (FR-84).
func (h *Handler) serveAdvertisement(w http.ResponseWriter, r *http.Request, mi *Mirror) {
	ctx := r.Context()
	if err := mi.ensure(ctx); err != nil {
		h.mgr.dropIfAbsent(mi)
		if ctx.Err() == nil {
			upstreamError(w, err)
		}
		return
	}
	if err := mi.refresh(ctx, modeCached); err != nil {
		if ctx.Err() != nil {
			return
		}
		h.mgr.met.staleServed.WithLabelValues(mi.remote.cfg.Name).Inc()
		w.Header().Set("X-Cache", "STALE")
	}

	proto := gitProtocol(r)
	release, err := h.mgr.acquireSlot(ctx)
	if err != nil {
		return
	}
	defer release()
	t0 := time.Now()
	env := []string{"GIT_PROTOCOL=" + proto}
	out, err := h.mgr.run.output(ctx, "", env, nil, "upload-pack", "--stateless-rpc", "--advertise-refs", mi.dir)
	h.mgr.met.uploadPack.WithLabelValues(mi.remote.cfg.Name, "advertise").Observe(time.Since(t0).Seconds())
	if err != nil {
		if ctx.Err() == nil {
			h.log.Warn("git upload-pack --advertise-refs failed", "repo", mi.key(), "error", err.Error())
			http.Error(w, "git error", http.StatusInternalServerError)
		}
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "application/x-git-upload-pack-advertisement")
	noCache(hd)
	var pre []byte
	if !isV2(proto) {
		// Like git http-backend: v0/v1 start with the service line; v2 doesn't.
		pre = append(pktLine("# service=git-upload-pack\n"), "0000"...)
	}
	hd.Set("Content-Length", strconv.Itoa(len(pre)+len(out)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pre)
	_, _ = w.Write(out) //nolint:gosec // G705: git protocol data with a git content type, not HTML
}

func pktLine(s string) []byte { return []byte(fmt.Sprintf("%04x%s", len(s)+4, s)) }

// serveUploadPack answers the POST that carries ls-refs (v2) or the
// want/have negotiation, and streams git upload-pack's output. It returns
// the operation for metrics.
func (h *Handler) serveUploadPack(w http.ResponseWriter, r *http.Request, mi *Mirror) string {
	ctx := r.Context()
	if ct := r.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-request" {
		http.Error(w, "unexpected content type", http.StatusUnsupportedMediaType)
		return "fetch"
	}
	var body io.Reader = r.Body
	switch r.Header.Get("Content-Encoding") {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "invalid gzip body", http.StatusBadRequest)
			return "fetch"
		}
		defer func() { _ = zr.Close() }()
		body = zr
	default:
		http.Error(w, "unsupported content encoding", http.StatusUnsupportedMediaType)
		return "fetch"
	}

	sp := &spool{dir: h.mgr.run.tmp, memLimit: 1 << 20}
	defer sp.Close()
	req, err := scanRequest(io.TeeReader(io.LimitReader(body, maxRequestBody+1), sp))
	if err == nil {
		_, err = io.Copy(io.Discard, io.TeeReader(io.LimitReader(body, maxRequestBody+1-sp.n), sp))
	}
	op := req.operation()
	switch {
	case err != nil:
		http.Error(w, "could not read request", http.StatusBadRequest)
		return op
	case sp.n > maxRequestBody:
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return op
	}
	if err := mi.ensure(ctx); err != nil {
		h.mgr.dropIfAbsent(mi)
		if ctx.Err() == nil {
			upstreamError(w, err)
		}
		return op
	}
	if len(req.wants) > 0 {
		mi.ensureObjects(ctx, req.wants)
	}
	in, err := sp.Reader()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return op
	}

	release, err := h.mgr.acquireSlot(ctx)
	if err != nil {
		return op
	}
	defer release()
	t0 := time.Now()
	defer func() { h.mgr.met.uploadPack.WithLabelValues(mi.remote.cfg.Name, op).Observe(time.Since(t0).Seconds()) }()

	cmd := h.mgr.run.command(ctx, "", []string{"GIT_PROTOCOL=" + gitProtocol(r)}, "upload-pack", "--stateless-rpc", mi.dir)
	out := &lazyWriter{w: w}
	stderr := &tailBuffer{max: 4096}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, stderr
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		msg := strings.TrimSpace(h.mgr.run.redact(stderr.String()))
		h.log.Warn("git upload-pack failed", "repo", mi.key(), "operation", op, "error", err.Error(), "stderr", msg)
		if !out.started {
			http.Error(w, "git upload-pack failed: "+msg, http.StatusInternalServerError)
		}
	}
	return op
}

// lazyWriter sends the response header with the first byte of output, so a
// git failure before any output can still become a 500.
type lazyWriter struct {
	w       http.ResponseWriter
	started bool
}

func (l *lazyWriter) Write(p []byte) (int, error) {
	if !l.started {
		l.started = true
		hd := l.w.Header()
		hd.Set("Content-Type", "application/x-git-upload-pack-result")
		noCache(hd)
		l.w.WriteHeader(http.StatusOK)
	}
	n, err := l.w.Write(p)
	if f, ok := l.w.(http.Flusher); ok {
		f.Flush() // keep progress (side-band) messages flowing
	}
	return n, err
}

// uploadRequest is what the proxy needs to know about an upload-pack request.
type uploadRequest struct {
	command string // v2 command; "" for v0
	wants   []string
	haves   bool
}

func (u uploadRequest) operation() string {
	switch u.command {
	case "ls-refs":
		return "ls-refs"
	case "", "fetch":
		if u.haves {
			return "fetch"
		}
		return "clone"
	default:
		return u.command
	}
}

var shaRe = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// scanRequest reads pkt-lines (v0 and v2 alike) and collects the wanted
// object IDs. It stops quietly at the first malformed packet; upload-pack
// sees the whole body and reports such errors itself.
func scanRequest(r io.Reader) (uploadRequest, error) {
	var u uploadRequest
	br := bufio.NewReaderSize(r, 64<<10)
	var hdr [4]byte
	buf := make([]byte, 65520)
	seen := map[string]bool{}
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return u, nil
			}
			return u, err
		}
		n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
		if err != nil {
			return u, nil
		}
		if n < 4 { // flush, delim, response-end
			continue
		}
		if n > 65520 {
			return u, nil
		}
		line := buf[:n-4]
		if _, err := io.ReadFull(br, line); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return u, nil
			}
			return u, err
		}
		s := strings.TrimSuffix(string(line), "\n")
		switch {
		case strings.HasPrefix(s, "command="):
			u.command = strings.TrimPrefix(s, "command=")
		case strings.HasPrefix(s, "want "):
			f := strings.Fields(s)
			if len(f) >= 2 && shaRe.MatchString(f[1]) && !seen[f[1]] {
				seen[f[1]] = true
				u.wants = append(u.wants, f[1])
			}
		case strings.HasPrefix(s, "have "):
			u.haves = true
		}
	}
}

// spool buffers a request body in memory, spilling to a temp file under
// git.storage/.tmp when it gets large.
type spool struct {
	dir      string
	memLimit int
	buf      bytes.Buffer
	f        *os.File
	n        int64
}

func (s *spool) Write(p []byte) (int, error) {
	s.n += int64(len(p))
	if s.f == nil && s.buf.Len()+len(p) <= s.memLimit {
		return s.buf.Write(p)
	}
	if s.f == nil {
		f, err := os.CreateTemp(s.dir, "req-")
		if err != nil {
			return 0, err
		}
		s.f = f
		if _, err := f.Write(s.buf.Bytes()); err != nil {
			return 0, err
		}
		s.buf.Reset()
	}
	return s.f.Write(p)
}

func (s *spool) Reader() (io.Reader, error) {
	if s.f == nil {
		return bytes.NewReader(s.buf.Bytes()), nil
	}
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return s.f, nil
}

func (s *spool) Close() {
	if s.f != nil {
		s.f.Close()
		os.Remove(s.f.Name())
	}
}

// authenticate finds the token in the path, a Bearer header or Basic auth
// (password; any user name), and validates it. git sends Basic credentials
// only after a 401 challenge, so a request without any gets one (FR-7).
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
		w.Header().Set("WWW-Authenticate", `Basic realm="yproxy"`)
		http.Error(w, msg, http.StatusUnauthorized)
	}
	if value == "" {
		h.mgr.met.authFail.WithLabelValues("missing").Inc()
		challenge("unauthorized")
		return nil, false
	}
	ip := clientIP(r)
	if h.limiter.Blocked(ip) {
		h.mgr.met.authFail.WithLabelValues("rate_limited").Inc()
		w.Header().Set("Retry-After", "5")
		http.Error(w, "too many invalid tokens", http.StatusTooManyRequests)
		return nil, false
	}
	tok, err := h.auth.Token(r.Context(), value)
	switch {
	case err == nil:
		return tok, true
	case errors.Is(err, auth.ErrDead):
		// Known token: 401 without counting it as a guess (SEC-3).
		h.mgr.met.authFail.WithLabelValues("expired_or_revoked").Inc()
		h.mgr.met.deadToken.WithLabelValues(tok.ID).Inc()
		h.warnDead(tok.ID)
		challenge("token expired or revoked")
	case errors.Is(err, auth.ErrUnknown):
		h.mgr.met.authFail.WithLabelValues("unknown").Inc()
		h.limiter.Allow(ip)
		challenge("unauthorized")
	case errors.Is(err, context.Canceled):
	default:
		h.log.Error("token lookup failed", "error", err.Error())
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}
	return nil, false
}

func (h *Handler) warnDead(id string) {
	h.warnMu.Lock()
	defer h.warnMu.Unlock()
	if time.Since(h.lastWarn[id]) < time.Minute {
		return
	}
	h.lastWarn[id] = time.Now()
	h.log.Warn("git request with expired or revoked token", "token_id", id)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
