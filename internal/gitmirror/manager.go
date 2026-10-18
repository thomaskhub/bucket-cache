// Package gitmirror is the read-only git mirror cache (requirements 5.8).
//
// Each allowed upstream repo gets a bare mirror on local disk with its own
// object store. Clients talk git smart HTTP to the proxy; every request is
// answered by the real `git upload-pack` (decision 8). Before a ref
// advertisement the mirror is compared with upstream by a cached, coalesced
// `ls-remote` and fetched when refs moved (FR-84), and commits a client
// wants that the mirror lacks are fetched once and kept under the hidden
// refs/proxy/keep/ namespace (FR-85).
package gitmirror

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/store"
)

var (
	// ErrNotFound means the remote is unknown, the repo is outside the
	// remote's allowlist, or (for admin calls) no mirror exists.
	ErrNotFound = errors.New("repository not found")
	// ErrBusy means a mirror can't be removed because it is in use.
	ErrBusy = errors.New("mirror is in use")
)

// keepPrefix holds commits fetched by SHA (FR-85). It is hidden from
// advertisements and never pruned (prune only touches the refspec targets).
const keepPrefix = "refs/proxy/keep/"

// maxKeepPerRequest bounds the upstream fetches one client request can cause.
const maxKeepPerRequest = 32

var nameRe = regexp.MustCompile(`^[a-z0-9_][a-z0-9._-]{0,99}$`)

// Options configures a Manager.
type Options struct {
	GitBinary     string // default "git" from PATH
	Logger        *slog.Logger
	Registerer    prometheus.Registerer
	HTTPClient    *http.Client // GitHub App API calls; default has a 30 s timeout
	PublicBaseURL string       // for clone URLs in the admin API
	// AllowStore keeps allowlist entries added through the admin API. Without
	// it, only the config file's allow patterns apply.
	AllowStore AllowStore
}

// AllowStore persists runtime allowlist entries (implemented by store.Store).
type AllowStore interface {
	ListGitAllow(ctx context.Context) ([]store.GitAllow, error)
	AddGitAllow(ctx context.Context, a store.GitAllow) error
	DeleteGitAllow(ctx context.Context, remote, pattern string) error
}

type remote struct {
	cfg   config.GitRemote
	base  string // upstream base URL without trailing slash
	creds credentials
}

// refspecs returns the namespaces mirrored from upstream (FR-83).
func (r *remote) refspecs() []string {
	s := []string{"+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"}
	if r.cfg.IncludePullRefs {
		s = append(s, "+refs/pull/*:refs/pull/*")
	}
	return s
}

func (r *remote) namespaces() []string {
	n := []string{"refs/heads/", "refs/tags/"}
	if r.cfg.IncludePullRefs {
		n = append(n, "refs/pull/")
	}
	return n
}

// Manager owns all mirrors.
type Manager struct {
	cfg     *config.Git
	run     *runner
	log     *slog.Logger
	met     *gitMetrics
	remotes map[string]*remote
	order   []string // remote names in config order
	root    string   // <storage>/mirrors
	sem     chan struct{}
	baseURL string
	now     func() time.Time

	mu      sync.Mutex
	mirrors map[string]*Mirror // key: remote/owner/repo

	allowStore AllowStore
	allowMu    sync.RWMutex
	allowExtra map[string][]store.GitAllow // remote name -> runtime entries
}

// New checks the git binary, prepares the storage directory and loads the
// mirrors already on disk.
func New(ctx context.Context, cfg *config.Git, opt Options) (*Manager, error) {
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.DiscardHandler)
	}
	if opt.Registerer == nil {
		opt.Registerer = prometheus.NewRegistry()
	}
	if opt.HTTPClient == nil {
		opt.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	run, err := newRunner(opt.GitBinary, cfg.Storage)
	if err != nil {
		return nil, err
	}
	v, vs, err := run.version(ctx)
	if err != nil {
		return nil, err
	}
	if v[0] < minGitVersion[0] || (v[0] == minGitVersion[0] && v[1] < minGitVersion[1]) {
		return nil, fmt.Errorf("%s is too old; the git mirror needs git %d.%d or newer", vs, minGitVersion[0], minGitVersion[1])
	}
	n := cfg.MaxConcurrency
	if n == 0 {
		n = max(8, 4*runtime.NumCPU())
	}
	m := &Manager{
		cfg: cfg, run: run, log: opt.Logger, remotes: map[string]*remote{},
		root: filepath.Join(cfg.Storage, "mirrors"), sem: make(chan struct{}, n),
		baseURL: strings.TrimRight(opt.PublicBaseURL, "/"), now: time.Now, mirrors: map[string]*Mirror{},
		allowStore: opt.AllowStore, allowExtra: map[string][]store.GitAllow{},
	}
	for _, rc := range cfg.Remotes {
		creds, err := newCredentials(rc, run, opt.HTTPClient)
		if err != nil {
			return nil, err
		}
		m.remotes[rc.Name] = &remote{cfg: rc, base: strings.TrimRight(rc.URL, "/"), creds: creds}
		m.order = append(m.order, rc.Name)
	}
	if m.allowStore != nil {
		entries, err := m.allowStore.ListGitAllow(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading the git allowlist: %w", err)
		}
		for _, a := range entries {
			if _, ok := m.remotes[a.Remote]; ok { // entries of removed remotes stay dormant
				m.allowExtra[a.Remote] = append(m.allowExtra[a.Remote], a)
			}
		}
	}
	if err := os.MkdirAll(m.root, 0o750); err != nil {
		return nil, err
	}
	// Leftovers of interrupted clones and deletions.
	if ents, err := os.ReadDir(run.tmp); err == nil {
		for _, e := range ents {
			_ = os.RemoveAll(filepath.Join(run.tmp, e.Name()))
		}
	}
	m.met = newMetrics(opt.Registerer, m)
	m.scan()
	m.log.Info("git mirror ready", "git", vs, "storage", cfg.Storage, "mirrors", len(m.mirrors), "max_upload_packs", n)
	return m, nil
}

// SetExecHook lets tests observe the argv of every git command.
func (m *Manager) SetExecHook(f func(args []string)) { m.run.onExec = f }

// scan loads the mirrors that exist on disk.
func (m *Manager) scan() {
	for name, rm := range m.remotes {
		owners, _ := os.ReadDir(filepath.Join(m.root, name))
		for _, o := range owners {
			repos, _ := os.ReadDir(filepath.Join(m.root, name, o.Name()))
			for _, r := range repos {
				repo, ok := strings.CutSuffix(r.Name(), ".git")
				if !ok || !r.IsDir() || !nameRe.MatchString(o.Name()) || !nameRe.MatchString(repo) {
					continue
				}
				mi := m.newMirror(rm, o.Name(), repo)
				mi.present = true
				mi.loadMeta()
				m.mirrors[mi.key()] = mi
			}
		}
	}
}

func (m *Manager) newMirror(rm *remote, owner, repo string) *Mirror {
	return &Mirror{
		mgr: m, remote: rm, owner: owner, repo: repo,
		dir:     filepath.Join(m.root, rm.cfg.Name, owner, repo+".git"),
		missing: map[string]time.Time{},
	}
}

// normalise lowercases owner/repo, strips a ".git" suffix and validates the
// names (FR-81). It returns ok=false for names that can't be a repo.
func normalise(owner, repo string) (string, string, bool) {
	owner = strings.ToLower(owner)
	repo = strings.ToLower(repo)
	repo = strings.TrimSuffix(repo, ".git")
	if !nameRe.MatchString(owner) || !nameRe.MatchString(repo) || strings.HasSuffix(repo, ".lock") {
		return "", "", false
	}
	return owner, repo, true
}

// Allowed reports whether remote/owner/repo is configured and allowlisted.
// owner and repo must already be normalised.
func (m *Manager) Allowed(remoteName, owner, repo string) bool {
	rm, ok := m.remotes[remoteName]
	if !ok {
		return false
	}
	if rm.cfg.Allows(owner + "/" + repo) {
		return true
	}
	m.allowMu.RLock()
	defer m.allowMu.RUnlock()
	for _, a := range m.allowExtra[remoteName] {
		if config.MatchAllow([]string{a.Pattern}, owner+"/"+repo) {
			return true
		}
	}
	return false
}

// mirror returns the in-memory entry for an allowed repo, creating it (but
// not the mirror on disk) if needed.
func (m *Manager) mirror(remoteName, owner, repo string) (*Mirror, error) {
	owner, repo, ok := normalise(owner, repo)
	if !ok || !m.Allowed(remoteName, owner, repo) {
		return nil, ErrNotFound
	}
	key := remoteName + "/" + owner + "/" + repo
	m.mu.Lock()
	defer m.mu.Unlock()
	mi, ok := m.mirrors[key]
	if !ok {
		mi = m.newMirror(m.remotes[remoteName], owner, repo)
		m.mirrors[key] = mi
	}
	return mi, nil
}

// open returns the mirror and holds it in use (so it can't be deleted)
// until release is called.
func (m *Manager) open(remoteName, owner, repo string) (*Mirror, func(), error) {
	for {
		mi, err := m.mirror(remoteName, owner, repo)
		if err != nil {
			return nil, nil, err
		}
		if release, ok := mi.use(); ok {
			mi.touch()
			return mi, release, nil
		}
		// Deleted between lookup and use: the next lookup creates a new entry.
	}
}

func (m *Manager) list() []*Mirror {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Mirror, 0, len(m.mirrors))
	for _, mi := range m.mirrors {
		out = append(out, mi)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func (m *Manager) forget(mi *Mirror) {
	m.mu.Lock()
	if m.mirrors[mi.key()] == mi {
		delete(m.mirrors, mi.key())
	}
	m.mu.Unlock()
}

// acquireSlot waits for an upload-pack slot (FR-93).
func (m *Manager) acquireSlot(ctx context.Context) (func(), error) {
	select {
	case m.sem <- struct{}{}:
		m.met.activePacks.Inc()
		return func() { <-m.sem; m.met.activePacks.Dec() }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Mirror is one bare mirror repository.
type Mirror struct {
	mgr    *Manager
	remote *remote
	owner  string
	repo   string
	dir    string

	// fetchMu serialises everything that writes the repository: clone,
	// fetch, maintenance and removal. upload-pack only reads and runs
	// concurrently with fetches, as on any git server.
	fetchMu sync.Mutex
	// useMu is held shared while the mirror is used and exclusively while
	// it is removed.
	useMu   sync.RWMutex
	deleted bool // guarded by useMu

	mu        sync.Mutex
	present   bool // exists on disk
	meta      meta
	lastCheck time.Time
	checkErr  error
	flight    *flight
	missing   map[string]time.Time // SHAs upstream didn't have (negative cache)
}

type flight struct {
	done chan struct{}
	err  error
}

// meta is persisted as yproxy.json inside the mirror.
type meta struct {
	CreatedAt   time.Time  `json:"created_at"`
	LastAccess  time.Time  `json:"last_access"`
	LastFetch   *time.Time `json:"last_fetch,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
}

const metaFile = "yproxy.json"

func (mi *Mirror) key() string      { return mi.remote.cfg.Name + "/" + mi.owner + "/" + mi.repo }
func (mi *Mirror) name() string     { return mi.owner + "/" + mi.repo }
func (mi *Mirror) upstream() string { return mi.remote.base + "/" + mi.owner + "/" + mi.repo + ".git" }

func (mi *Mirror) use() (func(), bool) {
	mi.useMu.RLock()
	if mi.deleted {
		mi.useMu.RUnlock()
		return nil, false
	}
	return mi.useMu.RUnlock, true
}

func (mi *Mirror) touch() {
	mi.mu.Lock()
	mi.meta.LastAccess = mi.mgr.now().UTC()
	mi.mu.Unlock()
}

func (mi *Mirror) isPresent() bool {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	return mi.present
}

func (mi *Mirror) loadMeta() {
	b, err := os.ReadFile(filepath.Join(mi.dir, metaFile))
	if err == nil {
		_ = json.Unmarshal(b, &mi.meta)
	}
	if mi.meta.CreatedAt.IsZero() {
		mi.meta.CreatedAt = mi.mgr.now().UTC()
	}
	if mi.meta.LastAccess.IsZero() {
		mi.meta.LastAccess = mi.mgr.now().UTC()
	}
}

// saveMeta writes yproxy.json atomically. Call without mi.mu held.
func (mi *Mirror) saveMeta() {
	mi.mu.Lock()
	if !mi.present {
		mi.mu.Unlock()
		return
	}
	b, _ := json.MarshalIndent(mi.meta, "", "  ")
	mi.mu.Unlock()
	tmp := filepath.Join(mi.dir, metaFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //nolint:gosec // G703: mi.dir is built from validated names
		mi.mgr.log.Warn("writing mirror metadata failed", "repo", mi.key(), "error", err.Error())
		return
	}
	_ = os.Rename(tmp, filepath.Join(mi.dir, metaFile)) //nolint:gosec // G703: mi.dir is built from validated names
}

func (mi *Mirror) recordError(kind string, err error) {
	now := mi.mgr.now().UTC()
	mi.mu.Lock()
	mi.meta.LastError = kind + ": " + err.Error()
	mi.meta.LastErrorAt = &now
	mi.mu.Unlock()
	mi.mgr.met.fetchErrors.WithLabelValues(mi.remote.cfg.Name, kind).Inc()
	mi.mgr.log.Warn("git upstream operation failed", "repo", mi.key(), "kind", kind, "error", err.Error())
}

func (mi *Mirror) recordSuccess(fetched bool) {
	now := mi.mgr.now().UTC()
	mi.mu.Lock()
	mi.meta.LastSuccess = &now
	if fetched {
		mi.meta.LastFetch = &now
	}
	mi.mu.Unlock()
}

// upstreamEnv returns the credential environment for this repo's upstream.
func (mi *Mirror) upstreamEnv(ctx context.Context) ([]string, error) {
	h, err := mi.remote.creds.header(ctx, mi.owner, mi.repo)
	if err != nil {
		return nil, err
	}
	return credEnv(mi.remote.base, h), nil
}

func (mi *Mirror) git(ctx context.Context, env []string, stdin io.Reader, args ...string) ([]byte, error) {
	return mi.mgr.run.output(ctx, "", env, stdin, append([]string{"--git-dir=" + mi.dir}, args...)...)
}

// ensure creates the mirror on first use (FR-83). Concurrent first
// requests wait for one clone.
func (mi *Mirror) ensure(ctx context.Context) error {
	if mi.isPresent() {
		return nil
	}
	mi.fetchMu.Lock()
	defer mi.fetchMu.Unlock()
	if mi.isPresent() {
		return nil
	}
	// The clone isn't cancelled when the first client gives up, so the
	// clients waiting behind it don't start over; fetch_timeout bounds it.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mi.mgr.cfg.FetchTimeout.D())
	defer cancel()
	return mi.clone(cctx)
}

// mirrorConfig is written into every mirror. hideRefs keeps keep-refs out of
// advertisements (v0 and v2 ls-refs); the allow* settings let clients fetch
// by SHA (FR-82, FR-85). allowAnySHA1InWant is safe because every repo has
// its own object store, so it can only expose objects of this repo.
var mirrorConfig = [][2]string{
	{"core.logAllRefUpdates", "false"},
	{"uploadpack.hideRefs", "refs/proxy/"},
	{"uploadpack.allowFilter", "true"},
	{"uploadpack.allowAnySHA1InWant", "true"},
	{"uploadpack.allowReachableSHA1InWant", "true"},
	{"uploadpack.allowTipSHA1InWant", "true"},
	// Not uploadpack.allowRefInWant: with it, git (2.43) sends wanted-refs
	// before shallow-info and its own client rejects shallow v2 clones.
	{"maintenance.auto", "false"},
	{"repack.writeBitmaps", "true"},
}

func (mi *Mirror) clone(ctx context.Context) error {
	start := mi.mgr.now()
	name := mi.remote.cfg.Name
	tmp, err := os.MkdirTemp(mi.mgr.run.tmp, "clone-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }() // no-op after the rename
	fail := func(err error) error {
		mi.mgr.met.fetchErrors.WithLabelValues(name, "clone").Inc()
		mi.mgr.log.Warn("git clone failed", "repo", mi.key(), "error", err.Error())
		return err
	}
	if _, err := mi.mgr.run.output(ctx, "", nil, nil, "init", "--bare", "--quiet", "--template=", tmp); err != nil {
		return fail(err)
	}
	cfg := append(append([][2]string{}, mirrorConfig...), [2]string{"remote.origin.url", mi.upstream()})
	for _, kv := range cfg {
		if _, err := mi.mgr.run.output(ctx, "", nil, nil, "--git-dir="+tmp, "config", kv[0], kv[1]); err != nil {
			return fail(err)
		}
	}
	env, err := mi.upstreamEnv(ctx)
	if err != nil {
		return fail(err)
	}
	if err := mi.fetchInto(ctx, tmp, env, true); err != nil {
		return fail(err)
	}
	mi.syncHead(ctx, tmp, env)
	if err := os.MkdirAll(filepath.Dir(mi.dir), 0o750); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmp, mi.dir); err != nil {
		return fail(err)
	}
	now := mi.mgr.now().UTC()
	mi.mu.Lock()
	mi.present = true
	mi.meta = meta{CreatedAt: now, LastAccess: now, LastFetch: &now, LastSuccess: &now}
	mi.lastCheck, mi.checkErr = mi.mgr.now(), nil
	mi.mu.Unlock()
	mi.updateSize()
	mi.saveMeta()
	mi.mgr.met.fetches.WithLabelValues(name, "clone").Inc()
	mi.mgr.met.fetchDuration.WithLabelValues(name, "clone").Observe(mi.mgr.now().Sub(start).Seconds())
	mi.mgr.log.Info("git mirror created", "repo", mi.key(), "duration_ms", mi.mgr.now().Sub(start).Milliseconds())
	return nil
}

// fetchInto fetches the mirrored namespaces from upstream into gitDir.
func (mi *Mirror) fetchInto(ctx context.Context, gitDir string, env []string, initial bool) error {
	args := []string{"--git-dir=" + gitDir, "fetch", "--quiet", "--no-tags", "--no-auto-maintenance", "--no-write-fetch-head"}
	if !initial && *mi.remote.cfg.Prune {
		args = append(args, "--prune")
	}
	args = append(args, mi.upstream())
	args = append(args, mi.remote.refspecs()...)
	_, err := mi.mgr.run.output(ctx, "", env, nil, args...)
	return err
}

// syncHead points HEAD at upstream's default branch, so clones through the
// proxy check out the same branch as clones from upstream.
func (mi *Mirror) syncHead(ctx context.Context, gitDir string, env []string) {
	hctx, cancel := context.WithTimeout(ctx, max(mi.remote.cfg.UpstreamTimeout.D(), 10*time.Second))
	defer cancel()
	out, err := mi.mgr.run.output(hctx, "", env, nil, "--git-dir="+gitDir, "ls-remote", "--symref", mi.upstream(), "HEAD")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		target, ok := strings.CutPrefix(line, "ref: ")
		if !ok {
			continue
		}
		target, _, _ = strings.Cut(target, "\t")
		if !strings.HasPrefix(target, "refs/heads/") {
			return
		}
		cur, _ := mi.mgr.run.output(ctx, "", nil, nil, "--git-dir="+gitDir, "symbolic-ref", "HEAD")
		if strings.TrimSpace(string(cur)) != target {
			_, _ = mi.mgr.run.output(ctx, "", nil, nil, "--git-dir="+gitDir, "symbolic-ref", "HEAD", target)
		}
		return
	}
}

// refreshMode says how much a refresh may skip.
type refreshMode int

const (
	modeCached refreshMode = iota // use the ls_remote_cache result if recent (client requests)
	modeCheck                     // always compare with upstream (background refresh)
	modeForce                     // always fetch (admin refresh, FR-86)
)

// refresh makes the mirror match upstream (FR-84). Concurrent callers share
// one check. It returns the check's error; callers serve the existing
// mirror anyway (FR-87).
func (mi *Mirror) refresh(ctx context.Context, mode refreshMode) error {
	name := mi.remote.cfg.Name
	for {
		mi.mu.Lock()
		if mode == modeCached && mi.flight == nil && !mi.lastCheck.IsZero() &&
			mi.mgr.now().Sub(mi.lastCheck) < mi.remote.cfg.LsRemoteCache.D() {
			err := mi.checkErr
			mi.mu.Unlock()
			mi.mgr.met.lsRemote.WithLabelValues(name, "cache_hit").Inc()
			return err
		}
		if f := mi.flight; f != nil {
			mi.mu.Unlock()
			select {
			case <-f.done:
			case <-ctx.Done():
				return ctx.Err()
			}
			if mode != modeForce {
				return f.err
			}
			continue // a forced refresh runs its own fetch
		}
		f := &flight{done: make(chan struct{})}
		mi.flight = f
		mi.mu.Unlock()

		// Detached: the result is shared, so one client leaving mustn't cancel it.
		f.err = mi.doRefresh(context.WithoutCancel(ctx), mode)
		mi.mu.Lock()
		mi.flight = nil
		mi.lastCheck, mi.checkErr = mi.mgr.now(), f.err
		mi.mu.Unlock()
		close(f.done)
		return f.err
	}
}

func (mi *Mirror) doRefresh(ctx context.Context, mode refreshMode) error {
	name := mi.remote.cfg.Name
	env, err := mi.upstreamEnv(ctx)
	if err != nil {
		mi.recordError("credentials", err)
		return err
	}
	if mode != modeForce {
		lctx, cancel := context.WithTimeout(ctx, mi.remote.cfg.UpstreamTimeout.D())
		up, err := mi.lsRemote(lctx, env)
		cancel()
		if err != nil {
			mi.mgr.met.lsRemote.WithLabelValues(name, "error").Inc()
			mi.recordError("ls-remote", err)
			return err
		}
		local, err := mi.localRefs(ctx)
		if err != nil {
			return err
		}
		if equalRefs(up, local) {
			mi.mgr.met.lsRemote.WithLabelValues(name, "unchanged").Inc()
			mi.recordSuccess(false)
			if mode == modeCheck {
				mi.syncHead(ctx, mi.dir, env)
			}
			return nil
		}
		mi.mgr.met.lsRemote.WithLabelValues(name, "changed").Inc()
	}
	return mi.fetch(ctx, env, mode != modeCached)
}

// fetch updates the mirror from upstream.
func (mi *Mirror) fetch(ctx context.Context, env []string, syncHead bool) error {
	name := mi.remote.cfg.Name
	mi.fetchMu.Lock()
	defer mi.fetchMu.Unlock()
	start := mi.mgr.now()
	fctx, cancel := context.WithTimeout(ctx, mi.mgr.cfg.FetchTimeout.D())
	defer cancel()
	if err := mi.fetchInto(fctx, mi.dir, env, false); err != nil {
		mi.recordError("fetch", err)
		return err
	}
	if syncHead {
		mi.syncHead(fctx, mi.dir, env)
	}
	mi.mgr.met.fetches.WithLabelValues(name, "fetch").Inc()
	mi.mgr.met.fetchDuration.WithLabelValues(name, "fetch").Observe(mi.mgr.now().Sub(start).Seconds())
	mi.recordSuccess(true)
	mi.updateSize()
	mi.saveMeta()
	return nil
}

// lsRemote lists upstream refs in the mirrored namespaces.
func (mi *Mirror) lsRemote(ctx context.Context, env []string) (map[string]string, error) {
	args := []string{"--git-dir=" + mi.dir, "ls-remote"}
	if !mi.remote.cfg.IncludePullRefs {
		args = append(args, "--heads", "--tags") // lets protocol v2 filter on the server
	}
	args = append(args, mi.upstream())
	out, err := mi.mgr.run.output(ctx, "", env, nil, args...)
	if err != nil {
		return nil, err
	}
	return mi.parseRefs(out, '\t'), nil
}

func (mi *Mirror) localRefs(ctx context.Context) (map[string]string, error) {
	args := []string{"for-each-ref", "--format=%(objectname) %(refname)"}
	for _, ns := range mi.remote.namespaces() {
		args = append(args, strings.TrimSuffix(ns, "/"))
	}
	out, err := mi.git(ctx, nil, nil, args...)
	if err != nil {
		return nil, err
	}
	return mi.parseRefs(out, ' '), nil
}

func (mi *Mirror) parseRefs(out []byte, sep byte) map[string]string {
	refs := map[string]string{}
	ns := mi.remote.namespaces()
	for _, line := range strings.Split(string(out), "\n") {
		sha, ref, ok := strings.Cut(line, string(sep))
		if !ok || strings.HasSuffix(ref, "^{}") {
			continue
		}
		for _, n := range ns {
			if strings.HasPrefix(ref, n) {
				refs[ref] = sha
				break
			}
		}
	}
	return refs
}

func equalRefs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// missingObjects returns the SHAs from wants that the mirror doesn't have.
func (mi *Mirror) missingObjects(ctx context.Context, wants []string) ([]string, error) {
	if len(wants) == 0 {
		return nil, nil
	}
	in := strings.Join(wants, "\n") + "\n"
	out, err := mi.git(ctx, nil, strings.NewReader(in), "cat-file", "--batch-check=%(objectname)")
	if err != nil {
		return nil, err
	}
	var missing []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if sha, ok := strings.CutSuffix(sc.Text(), " missing"); ok {
			missing = append(missing, sha)
		}
	}
	return missing, nil
}

// ensureObjects makes sure the wanted SHAs are in the mirror (FR-85): it
// first refreshes the branches (the SHA may just be new), then fetches each
// remaining SHA by itself and keeps it under refs/proxy/keep/<sha>.
func (mi *Mirror) ensureObjects(ctx context.Context, wants []string) {
	missing, err := mi.missingObjects(ctx, wants)
	if err != nil || len(missing) == 0 {
		return
	}
	if mi.refresh(ctx, modeCached) == nil {
		if missing, err = mi.missingObjects(ctx, missing); err != nil || len(missing) == 0 {
			return
		}
	}
	now := mi.mgr.now()
	todo := missing[:0]
	mi.mu.Lock()
	for _, sha := range missing {
		if t, ok := mi.missing[sha]; ok && now.Sub(t) < time.Minute {
			continue
		}
		todo = append(todo, sha)
	}
	mi.mu.Unlock()
	if len(todo) > maxKeepPerRequest {
		todo = todo[:maxKeepPerRequest]
	}
	if len(todo) == 0 {
		return
	}
	env, err := mi.upstreamEnv(ctx)
	if err != nil {
		mi.recordError("credentials", err)
		return
	}
	name := mi.remote.cfg.Name
	mi.fetchMu.Lock()
	defer mi.fetchMu.Unlock()
	for _, sha := range todo {
		start := mi.mgr.now()
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mi.mgr.cfg.FetchTimeout.D())
		_, err := mi.mgr.run.output(fctx, "", env, nil, "--git-dir="+mi.dir, "fetch", "--quiet", "--no-tags",
			"--no-auto-maintenance", "--no-write-fetch-head", mi.upstream(), "+"+sha+":"+keepPrefix+sha)
		cancel()
		if err != nil {
			mi.mu.Lock()
			mi.missing[sha] = mi.mgr.now()
			for k, t := range mi.missing {
				if now.Sub(t) > time.Minute {
					delete(mi.missing, k)
				}
			}
			mi.mu.Unlock()
			mi.recordError("keep", err)
			continue
		}
		mi.mgr.met.fetches.WithLabelValues(name, "keep").Inc()
		mi.mgr.met.fetchDuration.WithLabelValues(name, "keep").Observe(mi.mgr.now().Sub(start).Seconds())
		mi.mgr.log.Info("fetched commit by SHA and kept it", "repo", mi.key(), "sha", sha)
	}
	mi.updateSize()
	mi.saveMeta()
}

// updateSize recomputes the mirror's disk usage.
func (mi *Mirror) updateSize() {
	var n int64
	_ = filepath.WalkDir(mi.dir, func(_ string, d fs.DirEntry, err error) error { //nolint:gosec // G703: mi.dir is built from validated names
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	mi.mu.Lock()
	mi.meta.SizeBytes = n
	mi.mu.Unlock()
}

// Status describes a mirror for the admin API and the Repositories page.
type Status struct {
	Remote      string     `json:"remote"`
	Repo        string     `json:"repo"`
	Upstream    string     `json:"upstream"`
	CloneURL    string     `json:"clone_url,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
	CreatedAt   time.Time  `json:"created_at"`
	LastAccess  time.Time  `json:"last_access"`
	LastFetch   *time.Time `json:"last_fetch,omitempty"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	Stale       bool       `json:"stale"`
}

func (mi *Mirror) status() Status {
	mi.mu.Lock()
	defer mi.mu.Unlock()
	s := Status{
		Remote: mi.remote.cfg.Name, Repo: mi.name(), Upstream: mi.upstream(),
		SizeBytes: mi.meta.SizeBytes, CreatedAt: mi.meta.CreatedAt, LastAccess: mi.meta.LastAccess,
		LastFetch: mi.meta.LastFetch, LastSuccess: mi.meta.LastSuccess,
		LastError: mi.meta.LastError, LastErrorAt: mi.meta.LastErrorAt, Stale: mi.checkErr != nil,
	}
	if mi.mgr.baseURL != "" {
		s.CloneURL = mi.mgr.baseURL + "/git/" + mi.key() + ".git"
	}
	return s
}

// statuses lists the mirrors that exist on disk.
func (m *Manager) statuses() []Status {
	var out []Status
	for _, mi := range m.list() {
		if mi.isPresent() {
			out = append(out, mi.status())
		}
	}
	return out
}

// Refresh fetches a repo now, creating the mirror if needed (FR-86; also
// used to pre-seed repos, FR-83).
func (m *Manager) Refresh(ctx context.Context, remoteName, owner, repo string) (Status, error) {
	mi, release, err := m.open(remoteName, owner, repo)
	if err != nil {
		return Status{}, err
	}
	defer release()
	if !mi.isPresent() {
		if err := mi.ensure(ctx); err != nil {
			m.dropIfAbsent(mi)
			return Status{}, err
		}
		return mi.status(), nil
	}
	err = mi.refresh(ctx, modeForce)
	return mi.status(), err
}

// dropIfAbsent removes the in-memory entry of a repo whose clone failed, so
// requests for repos that don't exist upstream don't accumulate entries.
func (m *Manager) dropIfAbsent(mi *Mirror) {
	if !mi.isPresent() {
		m.forget(mi)
	}
}

// Remove deletes a mirror (admin API). It fails with ErrBusy if the mirror
// stays in use for 30 seconds.
func (m *Manager) Remove(ctx context.Context, remoteName, owner, repo string) error {
	mi, err := m.mirror(remoteName, owner, repo)
	if err != nil {
		return err
	}
	if !mi.isPresent() {
		m.dropIfAbsent(mi)
		return ErrNotFound
	}
	deadline := time.Now().Add(30 * time.Second)
	for !mi.useMu.TryLock() {
		if time.Now().After(deadline) {
			return ErrBusy
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	m.removeLocked(mi, "admin")
	return nil
}

// removeLocked deletes the mirror; the caller holds mi.useMu exclusively.
func (m *Manager) removeLocked(mi *Mirror, reason string) {
	defer mi.useMu.Unlock()
	mi.fetchMu.Lock()
	defer mi.fetchMu.Unlock()
	mi.deleted = true
	m.forget(mi)
	mi.mu.Lock()
	mi.present = false
	size := mi.meta.SizeBytes
	mi.mu.Unlock()
	// Rename first so a half-deleted mirror is never served or re-scanned.
	trash := filepath.Join(m.run.tmp, fmt.Sprintf("trash-%d", time.Now().UnixNano()))
	if err := os.Rename(mi.dir, trash); err != nil {
		trash = mi.dir
	}
	if err := os.RemoveAll(trash); err != nil { //nolint:gosec // G703: trash is under git.storage, built from validated names
		m.log.Warn("removing mirror failed", "repo", mi.key(), "error", err.Error())
	}
	_ = os.Remove(filepath.Dir(mi.dir)) //nolint:gosec // G703: validated names; removes the owner directory if now empty
	m.met.evictions.WithLabelValues(mi.remote.cfg.Name, reason).Inc()
	m.log.Info("git mirror removed", "repo", mi.key(), "reason", reason, "size_bytes", size)
}

// Run does the background work until ctx is cancelled: pre-seeding repos,
// the refresh loop per remote (refresh_interval) and maintenance with
// eviction (FR-84, FR-89).
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, name := range m.order {
		rm := m.remotes[name]
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.seed(ctx, rm)
			m.refreshLoop(ctx, rm)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(m.cfg.MaintenanceInterval.D())
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Maintain(ctx)
			}
		}
	}()
	wg.Wait()
	for _, mi := range m.list() {
		mi.saveMeta() // persist last-access times
	}
}

func (m *Manager) seed(ctx context.Context, rm *remote) {
	for _, s := range rm.cfg.Seed {
		owner, repo, _ := strings.Cut(s, "/")
		mi, release, err := m.open(rm.cfg.Name, owner, repo)
		if err != nil {
			continue
		}
		if err := mi.ensure(ctx); err != nil {
			m.dropIfAbsent(mi)
		}
		release()
		if ctx.Err() != nil {
			return
		}
	}
}

func (m *Manager) refreshLoop(ctx context.Context, rm *remote) {
	t := time.NewTicker(rm.cfg.RefreshInterval.D())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, mi := range m.list() {
			if mi.remote != rm || !mi.isPresent() {
				continue
			}
			release, ok := mi.use()
			if !ok {
				continue
			}
			_ = mi.refresh(ctx, modeCheck)
			release()
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// Maintain runs `git maintenance run --auto` on every mirror, saves
// metadata and evicts mirrors (FR-89). It is called every
// maintenance_interval.
func (m *Manager) Maintain(ctx context.Context) {
	for _, mi := range m.list() {
		if ctx.Err() != nil {
			return
		}
		release, ok := mi.use()
		if !ok || !mi.isPresent() {
			if ok {
				release()
			}
			continue
		}
		mi.fetchMu.Lock()
		mctx, cancel := context.WithTimeout(ctx, m.cfg.FetchTimeout.D())
		_, err := mi.git(mctx, nil, nil, "maintenance", "run", "--auto", "--quiet")
		cancel()
		mi.fetchMu.Unlock()
		if err != nil && ctx.Err() == nil {
			m.met.maintenanceErr.WithLabelValues(mi.remote.cfg.Name).Inc()
			m.log.Warn("git maintenance failed", "repo", mi.key(), "error", err.Error())
		}
		mi.updateSize()
		mi.saveMeta()
		release()
	}
	m.evict()
}

// evict removes mirrors unused for evict_after, then the least recently
// used ones while the total is over max_size (down to 90 %). Mirrors in use
// are skipped and retried at the next run.
func (m *Manager) evict() {
	now := m.now()
	var present []*Mirror
	var total int64
	for _, mi := range m.list() {
		if !mi.isPresent() {
			continue
		}
		st := mi.status()
		if m.cfg.EvictAfter > 0 && now.Sub(st.LastAccess) > m.cfg.EvictAfter.D() {
			if mi.useMu.TryLock() {
				m.removeLocked(mi, "unused")
			}
			continue
		}
		present = append(present, mi)
		total += st.SizeBytes
	}
	limit := int64(m.cfg.MaxSize)
	if limit <= 0 || total <= limit {
		return
	}
	sort.Slice(present, func(i, j int) bool { return present[i].status().LastAccess.Before(present[j].status().LastAccess) })
	low := limit / 10 * 9
	for _, mi := range present {
		if total <= low {
			return
		}
		size := mi.status().SizeBytes
		if mi.useMu.TryLock() {
			m.removeLocked(mi, "size")
			total -= size
		}
	}
	if total > limit {
		m.log.Warn("git storage is over max_size and no more mirrors can be evicted", "bytes", total, "max_size", limit)
	}
}

// ReadyDetails summarises upstream state for /readyz (FR-87). It never
// makes the proxy unready: stale mirrors are still served.
func (m *Manager) ReadyDetails() any {
	type remoteState struct {
		Mirrors int      `json:"mirrors"`
		Stale   []string `json:"stale,omitempty"`
	}
	out := map[string]*remoteState{}
	for _, name := range m.order {
		out[name] = &remoteState{}
	}
	for _, st := range m.statuses() {
		rs := out[st.Remote]
		rs.Mirrors++
		if st.Stale {
			rs.Stale = append(rs.Stale, st.Repo)
		}
	}
	return out
}
