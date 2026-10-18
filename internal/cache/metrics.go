package cache

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/metrics"
)

// Metrics are the cache metrics for all buckets (FR-72).
type Metrics struct {
	requests   *prometheus.CounterVec
	hitBytes   *prometheus.CounterVec
	fillBytes  *prometheus.CounterVec
	fillErrors *prometheus.CounterVec
	evictions  *prometheus.CounterVec
	size       *prometheus.GaugeVec
	objects    *prometheus.GaugeVec
}

// NewMetrics creates the cache metrics and registers them with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := newMetrics()
	reg.MustRegister(m.requests, m.hitBytes, m.fillBytes, m.fillErrors, m.evictions, m.size, m.objects)
	return m
}

func newMetrics() *Metrics {
	ns, sub := metrics.Namespace, "cache"
	return &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "requests_total",
			Help: "Requests to cached buckets by result (HIT, MISS, STALE, BYPASS)."}, []string{"bucket", "result"}),
		hitBytes: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "hit_bytes_total",
			Help: "Bytes served from the disk cache instead of the backend."}, []string{"bucket"}),
		fillBytes: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "fill_bytes_total",
			Help: "Bytes fetched from the backend into the disk cache."}, []string{"bucket"}),
		fillErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "fill_errors_total",
			Help: "Cache fills that failed mid-transfer and were discarded."}, []string{"bucket"}),
		evictions: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "evictions_total",
			Help: "Objects evicted by the LRU sweeper."}, []string{"bucket"}),
		size: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Subsystem: sub, Name: "size_bytes",
			Help: "Bytes stored in the disk cache."}, []string{"bucket"}),
		objects: prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Subsystem: sub, Name: "objects",
			Help: "Objects stored in the disk cache."}, []string{"bucket"}),
	}
}

type bucketMetrics struct {
	m          *Metrics
	alias      string
	hitBytes   prometheus.Counter
	fillBytes  prometheus.Counter
	fillErrors prometheus.Counter
	evictions  prometheus.Counter
	size       prometheus.Gauge
	objects    prometheus.Gauge
}

func (m *Metrics) forBucket(alias string) bucketMetrics {
	return bucketMetrics{
		m: m, alias: alias,
		hitBytes:   m.hitBytes.WithLabelValues(alias),
		fillBytes:  m.fillBytes.WithLabelValues(alias),
		fillErrors: m.fillErrors.WithLabelValues(alias),
		evictions:  m.evictions.WithLabelValues(alias),
		size:       m.size.WithLabelValues(alias),
		objects:    m.objects.WithLabelValues(alias),
	}
}

func (b bucketMetrics) requests(result string) prometheus.Counter {
	return b.m.requests.WithLabelValues(b.alias, result)
}
