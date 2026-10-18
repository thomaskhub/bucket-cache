package cache

import (
	"log/slog"
	"path/filepath"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/config"
)

// ConfigFor builds the cache config of a bucket in cache mode.
func ConfigFor(root string, b config.Bucket) Config {
	c := Config{
		Dir: filepath.Join(root, b.Alias), Alias: b.Alias, MaxSize: int64(b.Cache.MaxSize),
		Revalidate: b.Cache.Freshness == "revalidate", MaxAge: b.Cache.MaxAge.D(), ServeStale: b.Cache.ServeStale,
		IdleTimeout:       b.Timeouts.Idle.D(),
		RevalidateTimeout: b.Timeouts.Connect.D() + b.Timeouts.FirstByte.D(),
	}
	if b.Cache.NegativeTTL != nil {
		c.NegativeTTL = b.Cache.NegativeTTL.D()
	}
	return c
}

// OpenAll opens the caches of every bucket with mode: cache, keyed by alias.
// On error the caches opened so far are closed.
func OpenAll(cfg *config.Config, log *slog.Logger, reg prometheus.Registerer) (map[string]*Store, error) {
	out := map[string]*Store{}
	if !cfg.CacheEnabled() {
		return out, nil
	}
	m := NewMetrics(reg)
	for _, b := range cfg.Buckets {
		if b.Mode != "cache" {
			continue
		}
		c := ConfigFor(cfg.Storage.CacheRoot, b)
		c.Log, c.Metrics = log, m
		s, err := New(c)
		if err != nil {
			CloseAll(out)
			return nil, err
		}
		out[b.Alias] = s
	}
	return out, nil
}

// CloseAll closes every cache in m.
func CloseAll(m map[string]*Store) {
	for _, s := range m {
		s.Close()
	}
}
