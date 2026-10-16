// Package metrics owns the Prometheus registry. All proxy metrics use the
// yproxy_ prefix (requirements FR-72).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/thomaskhub/yocto-cache-proxy/internal/version"
)

const Namespace = "yproxy"

// NewRegistry returns a registry with Go runtime, process and build metrics.
func NewRegistry() *prometheus.Registry {
	r := prometheus.NewRegistry()
	r.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "build_info",
		Help:      "Build information; always 1.",
	}, []string{"version", "commit"})
	build.WithLabelValues(version.Version, version.Commit).Set(1)
	r.MustRegister(build)
	return r
}
