package cache

import (
	"sort"
	"time"
)

// Kick asks the sweeper to check the watermarks now.
func (s *Store) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

func (s *Store) sweeper() {
	defer s.wg.Done()
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.kick:
		case <-t.C:
		}
		s.Sweep()
	}
}

// Sweep evicts the least recently used objects down to the low watermark
// once usage is above the high watermark (FR-53). It returns the number of
// objects evicted.
func (s *Store) Sweep() int {
	type cand struct {
		hash  string
		e     *entry
		atime time.Time
	}
	s.mu.Lock()
	if s.total <= s.high {
		s.mu.Unlock()
		return 0
	}
	need := s.total - s.low
	list := make([]cand, 0, len(s.index))
	for h, e := range s.index {
		list = append(list, cand{h, e, e.atime})
	}
	s.mu.Unlock()

	sort.Slice(list, func(i, j int) bool { return list[i].atime.Before(list[j].atime) })
	var hashes []string
	victims := map[*entry]time.Time{}
	for _, c := range list {
		if need <= 0 {
			break
		}
		hashes = append(hashes, c.hash)
		victims[c.e] = c.atime
		need -= c.e.meta.Size
	}
	// Skip objects that were read again since the list was made.
	n, bytes := s.removeHashes(hashes, func(e *entry) bool {
		at, ok := victims[e]
		return ok && !e.atime.After(at)
	})
	if n > 0 {
		s.evicted.Add(uint64(n))
		s.m.evictions.Add(float64(n))
		s.log.Info("cache evicted", "objects", n, "bytes", bytes)
	}
	return n
}
