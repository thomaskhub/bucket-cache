// Package cache is the per-bucket disk cache for buckets in `mode: cache`
// (requirements FR-50..FR-58).
//
// Each bucket has its own directory under the cache root (FR-58):
//
//	<root>/<alias>/tmp/                        fills in progress; emptied at startup
//	<root>/<alias>/objects/ab/<hash>.meta      JSON sidecar: key, size, ETag, ...
//	<root>/<alias>/objects/ab/<hash>-<id>.data object bytes
//
// <hash> is the hex SHA-256 of the alias and the object key, so a key never
// becomes part of a path: no traversal, and no trouble with long or odd keys.
// Every fill writes a data file with a fresh random <id>, and the sidecar
// names the data file it belongs to. A commit fsyncs both files, renames the
// data file into place and then atomically replaces the sidecar, so after a
// crash at any point there is the old object, the new one, or an orphan data
// file that the startup scan deletes. A sidecar whose data file is missing
// or has the wrong size is discarded too, so a partial file is never served
// (FR-51).
//
// The sidecar's modification time records the object's last access, so LRU
// order survives a restart. It is updated at most once a minute per object
// to keep hits free of disk writes.
package cache

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Cache status values for the X-Cache header and the access log (FR-71, FR-74).
const (
	Hit    = "HIT"
	Miss   = "MISS"
	Stale  = "STALE"
	Bypass = "BYPASS"
)

// Watermarks as fractions of max_size (FR-53): the sweeper starts above
// high and evicts down to low.
const (
	highWater = 0.95
	lowWater  = 0.85
)

const (
	touchEvery     = time.Minute      // how often a hit updates the sidecar mtime
	downFor        = 10 * time.Second // skip revalidation this long after a backend failure
	sweepEvery     = time.Minute
	maxNegative    = 100_000 // bound on negative-cache entries per bucket
	removeBatch    = 256     // objects removed per lock hold during eviction and purge
	dirPerm        = 0o750
	filePerm       = 0o640
	metaSuffix     = ".meta"
	dataSuffix     = ".data"
	tmpDirName     = "tmp"
	objectsDirName = "objects"
)

var (
	// ErrUncacheable means the object can't be cached (unknown size or
	// larger than max_size); the caller serves it without the cache.
	ErrUncacheable = errors.New("object can't be cached")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("cache closed")
)

// Meta is the sidecar stored next to each object.
type Meta struct {
	Key          string    `json:"key"`
	Data         string    `json:"data"` // data file name in the same directory
	Size         int64     `json:"size"`
	ETag         string    `json:"etag,omitempty"`
	ContentType  string    `json:"content_type,omitempty"`
	LastModified time.Time `json:"last_modified,omitzero"`
	// Validated is when the object was fetched or last revalidated.
	Validated time.Time `json:"validated"`
}

// Config configures one bucket's cache.
type Config struct {
	Dir         string // the bucket's directory, <cache_root>/<alias>
	Alias       string
	MaxSize     int64
	Revalidate  bool          // freshness: revalidate (else immutable)
	MaxAge      time.Duration // revalidate after this long
	NegativeTTL time.Duration // 0 disables the 404 cache
	ServeStale  bool
	// IdleTimeout aborts a fill when the backend sends nothing for this long.
	IdleTimeout time.Duration
	// RevalidateTimeout bounds a conditional request to the backend.
	RevalidateTimeout time.Duration
	Log               *slog.Logger
	Metrics           *Metrics
	Now               func() time.Time
}

type entry struct {
	meta    Meta
	atime   time.Time
	touched time.Time // last time the sidecar mtime was written
}

// Store is one bucket's cache.
type Store struct {
	cfg        Config
	tmp, objs  string
	high, low  int64
	log        *slog.Logger
	m          bucketMetrics
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	kick       chan struct{}
	hits, miss atomic.Uint64
	stale      atomic.Uint64
	saved      atomic.Int64
	evicted    atomic.Uint64
	downUntil  atomic.Int64 // unix nanoseconds

	mu     sync.Mutex
	closed bool
	index  map[string]*entry // by hash
	total  int64
	fills  map[string]*fill     // by hash
	neg    map[string]time.Time // key -> expiry
}

// New opens (or creates) a bucket's cache directory, removes leftover temp
// files, rebuilds the index and size accounting from the sidecars, and
// starts the LRU sweeper.
func New(cfg Config) (*Store, error) {
	if cfg.Alias == "" || cfg.Alias != filepath.Base(cfg.Alias) || strings.HasPrefix(cfg.Alias, ".") {
		return nil, fmt.Errorf("cache: invalid bucket alias %q", cfg.Alias)
	}
	if cfg.MaxSize <= 0 {
		return nil, errors.New("cache: max_size must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = newMetrics()
	}
	s := &Store{
		cfg: cfg, tmp: filepath.Join(cfg.Dir, tmpDirName), objs: filepath.Join(cfg.Dir, objectsDirName),
		high: int64(float64(cfg.MaxSize) * highWater), low: int64(float64(cfg.MaxSize) * lowWater),
		log: cfg.Log.With("bucket", cfg.Alias), m: cfg.Metrics.forBucket(cfg.Alias),
		kick: make(chan struct{}, 1), index: map[string]*entry{}, fills: map[string]*fill{}, neg: map[string]time.Time{},
	}
	// Temp files are fills that never committed: a crash or a kill mid-transfer.
	if err := os.RemoveAll(s.tmp); err != nil {
		return nil, fmt.Errorf("cache %s: cleaning temp files: %w", cfg.Alias, err)
	}
	for _, d := range []string{s.tmp, s.objs} {
		if err := os.MkdirAll(d, dirPerm); err != nil {
			return nil, fmt.Errorf("cache %s: %w", cfg.Alias, err)
		}
	}
	if err := s.scan(); err != nil {
		return nil, fmt.Errorf("cache %s: scanning: %w", cfg.Alias, err)
	}
	s.updateGauges()
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.sweeper()
	s.Kick()
	return s, nil
}

// Close stops the sweeper and aborts fills in progress; their temp files are
// removed. Readers of committed objects are not affected.
func (s *Store) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

// Alias returns the bucket alias.
func (s *Store) Alias() string { return s.cfg.Alias }

// ServeStale reports whether stale objects may be served when the backend fails (FR-56).
func (s *Store) ServeStale() bool { return s.cfg.ServeStale }

// RevalidateTimeout bounds a conditional backend request.
func (s *Store) RevalidateTimeout() time.Duration { return s.cfg.RevalidateTimeout }

func (s *Store) hash(key string) string {
	sum := sha256.Sum256([]byte(s.cfg.Alias + "\x00" + key))
	return hex.EncodeToString(sum[:])
}

func (s *Store) dirFor(hash string) string   { return filepath.Join(s.objs, hash[:2]) }
func (s *Store) metaPath(hash string) string { return filepath.Join(s.dirFor(hash), hash+metaSuffix) }
func (s *Store) dataPath(hash, data string) string {
	return filepath.Join(s.dirFor(hash), filepath.Base(data))
}

// scan rebuilds the index from the sidecars and deletes anything that isn't
// a complete, committed object.
func (s *Store) scan() error {
	subs, err := os.ReadDir(s.objs)
	if err != nil {
		return err
	}
	var bad, orphans int
	for _, sub := range subs {
		dir := filepath.Join(s.objs, sub.Name())
		if !sub.IsDir() {
			_ = os.Remove(dir)
			continue
		}
		files, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		used := map[string]bool{}
		for _, f := range files {
			name := f.Name()
			hash, ok := strings.CutSuffix(name, metaSuffix)
			if !ok {
				continue
			}
			e, ok := s.loadEntry(dir, hash, f)
			if !ok {
				bad++
				_ = os.Remove(filepath.Join(dir, name))
				continue
			}
			used[e.meta.Data] = true
			s.index[hash] = e
			s.total += e.meta.Size
		}
		for _, f := range files {
			if name := f.Name(); !strings.HasSuffix(name, metaSuffix) && !used[name] {
				orphans++
				_ = os.Remove(filepath.Join(dir, name))
			}
		}
	}
	s.log.Info("cache loaded", "objects", len(s.index), "bytes", s.total, "discarded_sidecars", bad, "orphan_files", orphans)
	return nil
}

func (s *Store) loadEntry(dir, hash string, f fs.DirEntry) (*entry, bool) {
	info, err := f.Info()
	if err != nil {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(dir, f.Name()))
	if err != nil {
		return nil, false
	}
	var m Meta
	if json.Unmarshal(b, &m) != nil || s.hash(m.Key) != hash || hash[:2] != filepath.Base(dir) ||
		!strings.HasPrefix(m.Data, hash+"-") || !strings.HasSuffix(m.Data, dataSuffix) || m.Data != filepath.Base(m.Data) {
		return nil, false
	}
	st, err := os.Stat(filepath.Join(dir, m.Data))
	if err != nil || !st.Mode().IsRegular() || st.Size() != m.Size {
		return nil, false
	}
	return &entry{meta: m, atime: info.ModTime(), touched: info.ModTime()}, true
}

// Lookup returns the metadata of a cached object and records the access.
// It never touches the backend, so HEAD hits are answered from memory (FR-8).
func (s *Store) Lookup(key string) (Meta, bool) {
	h := s.hash(key)
	now := s.cfg.Now()
	s.mu.Lock()
	e := s.index[h]
	if e == nil {
		s.mu.Unlock()
		return Meta{}, false
	}
	e.atime = now
	touch := now.Sub(e.touched) >= touchEvery
	if touch {
		e.touched = now
	}
	m := e.meta
	s.mu.Unlock()
	if touch {
		_ = os.Chtimes(s.metaPath(h), now, now)
	}
	return m, true
}

// Fresh reports whether m can be served without revalidation (FR-54).
func (s *Store) Fresh(m Meta) bool {
	return !s.cfg.Revalidate || s.cfg.Now().Sub(m.Validated) < s.cfg.MaxAge
}

// OpenData opens a cached object's bytes. If the file has gone missing or
// has the wrong size, the entry is dropped and fs.ErrNotExist returned.
func (s *Store) OpenData(m Meta) (*os.File, error) {
	h := s.hash(m.Key)
	f, err := os.Open(s.dataPath(h, m.Data))
	if err == nil {
		st, serr := f.Stat()
		if serr == nil && st.Size() == m.Size {
			return f, nil
		}
		f.Close()
	}
	s.log.Warn("cached object is damaged; dropping it", "key", m.Key)
	s.Remove(m)
	return nil, fs.ErrNotExist
}

// Validated records a successful revalidation of m (FR-54). The sidecar is
// rewritten so the new time survives a restart; losing that write in a crash
// only costs one extra revalidation.
func (s *Store) Validated(m Meta) {
	h := s.hash(m.Key)
	m.Validated = s.cfg.Now()
	tmp, err := s.writeMetaTemp(m, false)
	if err != nil {
		s.log.Warn("updating cache metadata failed", "error", err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.index[h]
	if e == nil || e.meta.Data != m.Data {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, s.metaPath(h)); err != nil {
		_ = os.Remove(tmp)
		return
	}
	e.meta = m
}

// Remove drops the cached object m, if it is still the current version.
func (s *Store) Remove(m Meta) {
	h := s.hash(m.Key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.index[h]; e != nil && e.meta.Data == m.Data {
		s.removeLocked(h, e)
	}
	s.updateGaugesLocked()
}

func (s *Store) removeLocked(h string, e *entry) {
	delete(s.index, h)
	s.total -= e.meta.Size
	_ = os.Remove(s.metaPath(h))
	_ = os.Remove(s.dataPath(h, e.meta.Data))
}

// MarkBackendDown records a failed revalidation (FR-56).
func (s *Store) MarkBackendDown() { s.downUntil.Store(s.cfg.Now().Add(downFor).UnixNano()) }

// BackendDown reports whether a revalidation failed in the last few seconds.
func (s *Store) BackendDown() bool { return s.cfg.Now().UnixNano() < s.downUntil.Load() }

// Missing reports whether key is in the negative cache (FR-55).
func (s *Store) Missing(key string) bool {
	if s.cfg.NegativeTTL <= 0 {
		return false
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.neg[key]
	if ok && !now.Before(exp) {
		delete(s.neg, key)
		return false
	}
	return ok
}

// SetMissing records a backend 404 for negative_ttl.
func (s *Store) SetMissing(key string) {
	if s.cfg.NegativeTTL <= 0 {
		return
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.neg) >= maxNegative {
		for k, exp := range s.neg {
			if !now.Before(exp) {
				delete(s.neg, k)
			}
		}
		if len(s.neg) >= maxNegative {
			clear(s.neg)
		}
	}
	s.neg[key] = now.Add(s.cfg.NegativeTTL)
}

// Record counts a served request for the stats and metrics. Bytes served
// from disk (HIT or STALE) count as saved backend traffic (FR-57).
func (s *Store) Record(status string, bytes int64) {
	s.m.requests(status).Inc()
	switch status {
	case Hit, Stale:
		if status == Hit {
			s.hits.Add(1)
		} else {
			s.stale.Add(1)
		}
		s.saved.Add(bytes)
		s.m.hitBytes.Add(float64(bytes))
	case Miss:
		s.miss.Add(1)
	}
}

// Stats is the cache summary shown by the API and UI (FR-57).
type Stats struct {
	Alias      string  `json:"alias"`
	MaxSize    int64   `json:"max_size"`
	Size       int64   `json:"size"`
	Objects    int     `json:"objects"`
	Filling    int     `json:"filling"`
	Hits       uint64  `json:"hits"`
	Stale      uint64  `json:"stale"`
	Misses     uint64  `json:"misses"`
	HitRatio   float64 `json:"hit_ratio"`
	BytesSaved int64   `json:"bytes_saved"`
	Evictions  uint64  `json:"evictions"`
	Freshness  string  `json:"freshness"`
}

// Stats returns counters since startup and the current size.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	st := Stats{Alias: s.cfg.Alias, MaxSize: s.cfg.MaxSize, Size: s.total, Objects: len(s.index), Filling: len(s.fills)}
	s.mu.Unlock()
	st.Hits, st.Stale, st.Misses = s.hits.Load(), s.stale.Load(), s.miss.Load()
	if n := st.Hits + st.Stale + st.Misses; n > 0 {
		st.HitRatio = float64(st.Hits+st.Stale) / float64(n)
	}
	st.BytesSaved, st.Evictions = s.saved.Load(), s.evicted.Load()
	st.Freshness = "immutable"
	if s.cfg.Revalidate {
		st.Freshness = "revalidate"
	}
	return st
}

// Purge removes cached objects whose key matches: everything when key and
// prefix are empty, one key, or every key under prefix (FR-57). Fills in
// progress for matching keys are not committed. It returns the number of
// objects and bytes removed.
func (s *Store) Purge(key, prefix string) (int, int64) {
	match := func(k string) bool {
		if key != "" {
			return k == key
		}
		return strings.HasPrefix(k, prefix)
	}
	s.mu.Lock()
	var hashes []string
	for h, e := range s.index {
		if match(e.meta.Key) {
			hashes = append(hashes, h)
		}
	}
	for _, fl := range s.fills {
		if match(fl.key) {
			fl.discard = true
		}
	}
	for k := range s.neg {
		if match(k) {
			delete(s.neg, k)
		}
	}
	s.mu.Unlock()
	n, bytes := s.removeHashes(hashes, func(e *entry) bool { return match(e.meta.Key) })
	s.log.Info("cache purged", "objects", n, "bytes", bytes, "prefix", prefix, "key", key)
	return n, bytes
}

// removeHashes deletes entries in batches so a big purge or eviction doesn't
// hold the lock for long. still re-checks each entry under the lock.
func (s *Store) removeHashes(hashes []string, still func(*entry) bool) (int, int64) {
	var n int
	var bytes int64
	for len(hashes) > 0 {
		batch := hashes[:min(removeBatch, len(hashes))]
		hashes = hashes[len(batch):]
		s.mu.Lock()
		for _, h := range batch {
			if e := s.index[h]; e != nil && still(e) {
				n++
				bytes += e.meta.Size
				s.removeLocked(h, e)
			}
		}
		s.updateGaugesLocked()
		s.mu.Unlock()
	}
	return n, bytes
}

func (s *Store) updateGauges() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateGaugesLocked()
}

func (s *Store) updateGaugesLocked() {
	s.m.size.Set(float64(s.total))
	s.m.objects.Set(float64(len(s.index)))
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// writeMetaTemp writes m to a new file in tmp/ and returns its path.
func (s *Store) writeMetaTemp(m Meta, sync bool) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(s.tmp, "meta-*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(b)
	if err == nil && sync {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(f.Name(), filePerm)
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
