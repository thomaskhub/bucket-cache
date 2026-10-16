package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPLimiter rate-limits failures per client IP. It's only applied to unknown
// credentials, so a build with an expired token can't lock out other builds
// behind the same NAT (SEC-3).
type IPLimiter struct {
	rate  rate.Limit
	burst int

	mu      sync.Mutex
	clients map[string]*ipEntry
	lastGC  time.Time
}

type ipEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewIPLimiter allows perSecond failures per IP with the given burst.
func NewIPLimiter(perSecond float64, burst int) *IPLimiter {
	return &IPLimiter{rate: rate.Limit(perSecond), burst: burst, clients: map[string]*ipEntry{}, lastGC: time.Now()}
}

// Allow records one failure for ip and reports whether it's within the limit.
func (l *IPLimiter) Allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastGC) > time.Minute {
		for k, e := range l.clients {
			if now.Sub(e.seen) > 10*time.Minute {
				delete(l.clients, k)
			}
		}
		l.lastGC = now
	}
	e, ok := l.clients[ip]
	if !ok {
		e = &ipEntry{lim: rate.NewLimiter(l.rate, l.burst)}
		l.clients[ip] = e
	}
	e.seen = now
	return e.lim.AllowN(now, 1)
}

// Blocked reports whether ip is currently over the limit, without counting.
func (l *IPLimiter) Blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.clients[ip]
	return ok && e.lim.TokensAt(time.Now()) < 1
}
