package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"time"
)

// FetchFunc fetches a whole object from the backend. The returned Meta needs
// Size, ETag, ContentType and LastModified; the cache fills in the rest.
type FetchFunc func(ctx context.Context) (Meta, io.ReadCloser, error)

// fill is one backend download into a temp file. Every request for the key
// while it runs reads from the same file as it grows (FR-50, FR-52).
//
// The download runs on the store's context, not a client's: when the client
// that started it disconnects, the fill still completes and is committed, so
// the bytes already fetched aren't wasted and the next build gets a hit. A
// stalled backend is cut off by the idle timeout, and Close aborts fills on
// shutdown. A fill that fails is never committed; its temp file is deleted.
type fill struct {
	key, hash string
	ready     chan struct{} // closed once meta is known or the fetch failed
	readyOnce sync.Once
	meta      Meta
	discard   bool // purged while filling; guarded by Store.mu

	mu      sync.Mutex
	cond    *sync.Cond
	path    string // current location of the data: temp file, then final
	written int64
	done    bool // all bytes are on disk
	err     error
}

func newFill(key, hash string) *fill {
	fl := &fill{key: key, hash: hash, ready: make(chan struct{})}
	fl.cond = sync.NewCond(&fl.mu)
	return fl
}

func (fl *fill) markReady() { fl.readyOnce.Do(func() { close(fl.ready) }) }

func (fl *fill) fail(err error) {
	fl.mu.Lock()
	if !fl.done {
		fl.err = err
	}
	fl.cond.Broadcast()
	fl.mu.Unlock()
	fl.markReady()
}

func (fl *fill) advance(n int) {
	fl.mu.Lock()
	fl.written += int64(n)
	fl.cond.Broadcast()
	fl.mu.Unlock()
}

// Get returns a reader for key: the committed object if it is cached, or
// else a reader that follows a fill, starting one with fetch if none runs.
// Concurrent callers share one fill. Get waits until the backend has
// answered, so a fetch error (for example a 404) is returned here and no
// response has to be started first.
func (s *Store) Get(ctx context.Context, key string, fetch FetchFunc) (*Reader, error) {
	h := s.hash(key)
	for attempt := 0; ; attempt++ {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, ErrClosed
		}
		if e := s.index[h]; e != nil {
			m := e.meta
			s.mu.Unlock()
			f, err := s.OpenData(m)
			if err != nil {
				continue
			}
			return newReader(ctx, doneFill(m), f), nil
		}
		fl := s.fills[h]
		if fl == nil {
			fl = newFill(key, h)
			s.fills[h] = fl
			s.wg.Add(1)
			go s.run(fl, fetch)
		}
		s.mu.Unlock()

		select {
		case <-fl.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		fl.mu.Lock()
		ferr := fl.err
		var f *os.File
		var err error
		if ferr == nil {
			f, err = os.Open(fl.path)
		}
		fl.mu.Unlock()
		if ferr != nil {
			return nil, ferr
		}
		if err == nil {
			return newReader(ctx, fl, f), nil
		}
		// The file vanished between commit and open (a purge or eviction
		// raced us); look again.
		if errors.Is(err, fs.ErrNotExist) && attempt < 3 {
			continue
		}
		return nil, err
	}
}

func doneFill(m Meta) *fill {
	fl := newFill(m.Key, "")
	fl.meta, fl.written, fl.done = m, m.Size, true
	fl.markReady()
	return fl
}

func (s *Store) run(fl *fill, fetch FetchFunc) {
	defer s.wg.Done()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	var tmpData, tmpMeta string
	err := s.download(ctx, cancel, fl, fetch, &tmpData, &tmpMeta)
	if err == nil {
		err = s.commit(fl, tmpData, tmpMeta)
	}
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.fills[fl.hash] == fl {
		delete(s.fills, fl.hash)
	}
	s.mu.Unlock()
	fl.fail(err)
	if tmpData != "" {
		_ = os.Remove(tmpData)
	}
	if tmpMeta != "" {
		_ = os.Remove(tmpMeta)
	}
	// Errors before the first byte (404, timeouts) go back to the callers;
	// only failures mid-transfer are logged here.
	if tmpData != "" && !errors.Is(err, errDiscarded) {
		s.m.fillErrors.Inc()
		s.log.Warn("cache fill failed", "key", fl.key, "error", err.Error())
	}
}

var errDiscarded = errors.New("purged while filling")

func (s *Store) download(ctx context.Context, cancel context.CancelFunc, fl *fill, fetch FetchFunc, tmpData, tmpMeta *string) error {
	meta, body, err := fetch(ctx)
	if err != nil {
		return err
	}
	defer body.Close()
	if meta.Size < 0 || meta.Size > s.cfg.MaxSize {
		return ErrUncacheable
	}
	meta.Key = fl.key
	meta.Data = fl.hash + "-" + newID() + dataSuffix
	meta.Validated = s.cfg.Now()

	f, err := os.CreateTemp(s.tmp, "fill-*")
	if err != nil {
		return err
	}
	*tmpData = f.Name()
	defer f.Close()
	fl.meta = meta
	fl.mu.Lock()
	fl.path = f.Name()
	fl.mu.Unlock()
	fl.markReady()

	var idle *time.Timer
	if s.cfg.IdleTimeout > 0 {
		idle = time.AfterFunc(s.cfg.IdleTimeout, cancel)
		defer idle.Stop()
	}
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	var n int64
	for {
		k, rerr := body.Read(*buf)
		if k > 0 {
			if idle != nil {
				idle.Reset(s.cfg.IdleTimeout)
			}
			if _, werr := f.Write((*buf)[:k]); werr != nil {
				return werr
			}
			n += int64(k)
			s.m.fillBytes.Add(float64(k))
			fl.advance(k)
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return rerr
		}
		if n > meta.Size {
			break
		}
	}
	if n != meta.Size {
		return fmt.Errorf("backend sent %d of %d bytes: %w", n, meta.Size, io.ErrUnexpectedEOF)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := os.Chmod(f.Name(), filePerm); err != nil {
		return err
	}
	// Every byte is on disk: readers can finish even if the commit fails.
	fl.mu.Lock()
	fl.done = true
	fl.cond.Broadcast()
	fl.mu.Unlock()

	*tmpMeta, err = s.writeMetaTemp(meta, true)
	return err
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 256<<10); return &b }}

// commit moves a finished fill into place (FR-51): data file first, then
// the sidecar, which atomically replaces any older version.
func (s *Store) commit(fl *fill, tmpData, tmpMeta string) error {
	h, m := fl.hash, fl.meta
	dir := s.dirFor(h)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return err
	}
	s.mu.Lock()
	if fl.discard || s.closed {
		s.mu.Unlock()
		return errDiscarded
	}
	final := s.dataPath(h, m.Data)
	fl.mu.Lock()
	err := os.Rename(tmpData, final)
	if err == nil {
		if err = os.Rename(tmpMeta, s.metaPath(h)); err != nil {
			_ = os.Remove(final)
		}
	}
	if err == nil {
		fl.path = final
	}
	fl.mu.Unlock()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if old := s.index[h]; old != nil {
		s.total -= old.meta.Size
		_ = os.Remove(s.dataPath(h, old.meta.Data))
	}
	now := s.cfg.Now()
	s.index[h] = &entry{meta: m, atime: now, touched: now}
	s.total += m.Size
	delete(s.fills, h)
	delete(s.neg, fl.key)
	over := s.total > s.high
	s.updateGaugesLocked()
	s.mu.Unlock()
	syncDir(dir)
	if over {
		s.Kick()
	}
	return nil
}

// Reader reads a cached object or follows a fill in progress. It implements
// io.ReadSeeker over the whole object, so http.ServeContent can answer
// Range and conditional requests from it.
type Reader struct {
	fl   *fill
	f    *os.File
	off  int64
	ctx  context.Context
	stop func() bool
}

func newReader(ctx context.Context, fl *fill, f *os.File) *Reader {
	r := &Reader{fl: fl, f: f, ctx: ctx}
	// done is written by the fill goroutine, so it must be read under fl.mu.
	fl.mu.Lock()
	done := fl.done
	fl.mu.Unlock()
	if !done {
		// Wake a Read that waits for bytes when the client goes away.
		r.stop = context.AfterFunc(ctx, func() {
			fl.mu.Lock()
			fl.cond.Broadcast()
			fl.mu.Unlock()
		})
	}
	return r
}

// Meta returns the object's metadata.
func (r *Reader) Meta() Meta { return r.fl.meta }

func (r *Reader) Read(p []byte) (int, error) {
	fl := r.fl
	if r.off >= fl.meta.Size {
		return 0, io.EOF
	}
	fl.mu.Lock()
	for r.off >= fl.written && fl.err == nil && r.ctx.Err() == nil {
		fl.cond.Wait()
	}
	avail, err := fl.written-r.off, fl.err
	fl.mu.Unlock()
	if avail <= 0 {
		if err == nil {
			err = r.ctx.Err()
		}
		return 0, err
	}
	if int64(len(p)) > avail {
		p = p[:avail]
	}
	n, err := r.f.ReadAt(p, r.off)
	r.off += int64(n)
	if errors.Is(err, io.EOF) && n > 0 {
		err = nil
	}
	return n, err
}

func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += r.off
	case io.SeekEnd:
		offset += r.fl.meta.Size
	default:
		return 0, errors.New("invalid whence")
	}
	if offset < 0 {
		return 0, errors.New("negative position")
	}
	r.off = offset
	return offset, nil
}

// Close releases the file.
func (r *Reader) Close() {
	if r.stop != nil {
		r.stop()
	}
	r.f.Close()
}
