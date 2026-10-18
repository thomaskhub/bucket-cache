package gitmirror

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/metrics"
)

// gitMetrics are the git series of FR-72.
type gitMetrics struct {
	requests       *prometheus.CounterVec
	uploadPack     *prometheus.HistogramVec
	bytes          *prometheus.CounterVec
	fetches        *prometheus.CounterVec
	fetchErrors    *prometheus.CounterVec
	fetchDuration  *prometheus.HistogramVec
	lsRemote       *prometheus.CounterVec
	staleServed    *prometheus.CounterVec
	evictions      *prometheus.CounterVec
	authFail       *prometheus.CounterVec
	deadToken      *prometheus.CounterVec
	activePacks    prometheus.Gauge
	maintenanceErr *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer, m *Manager) *gitMetrics {
	ns, sub := metrics.Namespace, "git"
	g := &gitMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "requests_total",
			Help: "Git smart HTTP requests by remote, repo, operation (advertise, ls-refs, clone, fetch, push) and status code."},
			[]string{"remote", "repo", "operation", "code"}),
		uploadPack: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Subsystem: sub, Name: "upload_pack_duration_seconds",
			Help:    "Duration of git upload-pack runs by remote and operation.",
			Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600}}, []string{"remote", "operation"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "bytes_served_total",
			Help: "Git response bytes sent to clients."}, []string{"remote"}),
		fetches: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "upstream_fetches_total",
			Help: "Upstream clones and fetches by remote and kind (clone, fetch, keep)."}, []string{"remote", "kind"}),
		fetchErrors: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "upstream_fetch_errors_total",
			Help: "Failed upstream operations by remote and kind (clone, fetch, keep, ls-remote)."}, []string{"remote", "kind"}),
		fetchDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Subsystem: sub, Name: "upstream_fetch_duration_seconds",
			Help:    "Duration of upstream clones and fetches.",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300, 900, 1800}}, []string{"remote", "kind"}),
		lsRemote: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "ls_remote_total",
			Help: "Freshness checks by remote and result (cache_hit, unchanged, changed, error)."}, []string{"remote", "result"}),
		staleServed: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "stale_served_total",
			Help: "Ref advertisements served from the mirror because upstream was unreachable (FR-87)."}, []string{"remote"}),
		evictions: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "evictions_total",
			Help: "Mirrors removed by remote and reason (unused, size, admin)."}, []string{"remote", "reason"}),
		authFail: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "auth_failures_total",
			Help: "Rejected git requests by reason."}, []string{"reason"}),
		deadToken: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "dead_token_requests_total",
			Help: "Git requests with an expired or revoked token, by token ID."}, []string{"token_id"}),
		activePacks: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: sub, Name: "upload_pack_active",
			Help: "Running git upload-pack processes."}),
		maintenanceErr: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: sub, Name: "maintenance_errors_total",
			Help: "Failed git maintenance runs by remote."}, []string{"remote"}),
	}
	reg.MustRegister(g.requests, g.uploadPack, g.bytes, g.fetches, g.fetchErrors, g.fetchDuration, g.lsRemote,
		g.staleServed, g.evictions, g.authFail, g.deadToken, g.activePacks, g.maintenanceErr, &mirrorCollector{m: m})
	return g
}

// mirrorCollector reports per-mirror state at scrape time.
type mirrorCollector struct{ m *Manager }

var (
	descMirrors = prometheus.NewDesc(metrics.Namespace+"_git_mirrors", "Mirrored repositories by remote.", []string{"remote"}, nil)
	descSize    = prometheus.NewDesc(metrics.Namespace+"_git_mirror_size_bytes", "Disk size of each mirror (updated after fetches and maintenance).",
		[]string{"remote", "repo"}, nil)
	descTotal = prometheus.NewDesc(metrics.Namespace+"_git_storage_bytes", "Total disk size of all mirrors.", nil, nil)
	descAge   = prometheus.NewDesc(metrics.Namespace+"_git_seconds_since_last_refresh",
		"Seconds since the mirror last matched upstream (successful ls-remote check or fetch).", []string{"remote", "repo"}, nil)
	descStale = prometheus.NewDesc(metrics.Namespace+"_git_mirror_stale",
		"1 if the last upstream check of the mirror failed and it is served stale.", []string{"remote", "repo"}, nil)
)

func (c *mirrorCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descMirrors
	ch <- descSize
	ch <- descTotal
	ch <- descAge
	ch <- descStale
}

func (c *mirrorCollector) Collect(ch chan<- prometheus.Metric) {
	counts := map[string]int{}
	for _, r := range c.m.cfg.Remotes {
		counts[r.Name] = 0
	}
	var total int64
	now := time.Now()
	for _, st := range c.m.statuses() {
		counts[st.Remote]++
		total += st.SizeBytes
		ch <- prometheus.MustNewConstMetric(descSize, prometheus.GaugeValue, float64(st.SizeBytes), st.Remote, st.Repo)
		if st.LastSuccess != nil {
			ch <- prometheus.MustNewConstMetric(descAge, prometheus.GaugeValue, now.Sub(*st.LastSuccess).Seconds(), st.Remote, st.Repo)
		}
		stale := 0.0
		if st.Stale {
			stale = 1
		}
		ch <- prometheus.MustNewConstMetric(descStale, prometheus.GaugeValue, stale, st.Remote, st.Repo)
	}
	for r, n := range counts {
		ch <- prometheus.MustNewConstMetric(descMirrors, prometheus.GaugeValue, float64(n), r)
	}
	ch <- prometheus.MustNewConstMetric(descTotal, prometheus.GaugeValue, float64(total))
}
