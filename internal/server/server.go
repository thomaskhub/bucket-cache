// Package server runs the data and admin HTTP listeners.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/thomaskhub/yocto-cache-proxy/internal/config"
)

// Server owns both listeners. The data listener serves object and git
// traffic; the admin listener serves the UI, API, metrics and health checks
// so it can be kept off the build network (SEC-5).
type Server struct {
	cfg  *config.Config
	log  *slog.Logger
	reg  *prometheus.Registry
	data *http.Server
	adm  *http.Server

	// Data is the handler for object and git traffic. Later milestones
	// mount the S3 and git handlers here.
	Data *http.ServeMux
	// Admin is the handler for the UI and management API.
	Admin *http.ServeMux
}

// New builds a server from a loaded config.
func New(cfg *config.Config, log *slog.Logger, reg *prometheus.Registry) *Server {
	s := &Server{cfg: cfg, log: log, reg: reg, Data: http.NewServeMux(), Admin: http.NewServeMux()}

	s.Data.HandleFunc("GET /healthz", s.healthz)
	s.Admin.HandleFunc("GET /healthz", s.healthz)
	s.Admin.HandleFunc("GET /readyz", s.readyz)
	s.Admin.Handle("GET /metrics", s.metricsAuth(promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})))

	s.data = s.httpServer(cfg.Server.DataListen, s.Data)
	s.adm = s.httpServer(cfg.Server.AdminListen, s.Admin)
	return s
}

func (s *Server) httpServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: object and git responses can stream for a long time.
		IdleTimeout: 120 * time.Second,
		ErrorLog:    slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

// Run serves until ctx is cancelled, then drains in-flight requests for up
// to server.shutdown_grace (NFR-REL-2).
func (s *Server) Run(ctx context.Context) error {
	lnData, err := net.Listen("tcp", s.data.Addr)
	if err != nil {
		return fmt.Errorf("data listener: %w", err)
	}
	lnAdm, err := net.Listen("tcp", s.adm.Addr)
	if err != nil {
		lnData.Close()
		return fmt.Errorf("admin listener: %w", err)
	}

	tls := s.cfg.Server.TLS
	serve := func(srv *http.Server, ln net.Listener) error {
		if tls.Enabled() {
			return srv.ServeTLS(ln, tls.CertFile, tls.KeyFile)
		}
		return srv.Serve(ln)
	}
	scheme := "http"
	if tls.Enabled() {
		scheme = "https"
	}
	s.log.Info("listening", "data", lnData.Addr().String(), "admin", lnAdm.Addr().String(), "scheme", scheme)

	errc := make(chan error, 2)
	go func() { errc <- serve(s.data, lnData) }()
	go func() { errc <- serve(s.adm, lnAdm) }()

	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			s.shutdown()
			return err
		}
	}
	return s.shutdown()
}

func (s *Server) shutdown() error {
	grace := s.cfg.Server.ShutdownGrace.D()
	s.log.Info("shutting down", "grace", grace.String())
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, srv := range []*http.Server{s.data, s.adm} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = srv.Shutdown(ctx)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

type check struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// readyz reports whether the directories the proxy writes to are usable.
func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	checks := []check{writable("data_dir", filepath.Dir(s.cfg.Storage.DBPath))}
	if s.cfg.CacheEnabled() {
		checks = append(checks, writable("cache_root", s.cfg.Storage.CacheRoot))
	}
	if s.cfg.Git != nil {
		checks = append(checks, writable("git_storage", s.cfg.Git.Storage))
	}
	ready := true
	for _, c := range checks {
		ready = ready && c.OK
	}
	w.Header().Set("Content-Type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ready": ready, "checks": checks})
}

func writable(name, dir string) check {
	f, err := os.CreateTemp(dir, ".readyz-*")
	if err != nil {
		msg := err.Error()
		var pe *os.PathError
		if errors.As(err, &pe) {
			msg = pe.Err.Error() // keep the reason, drop the temp-file path
		}
		return check{Name: name, Error: "not writable: " + msg}
	}
	f.Close()
	os.Remove(f.Name())
	return check{Name: name, OK: true}
}

// metricsAuth requires the configured bearer token, if any, for /metrics.
func (s *Server) metricsAuth(next http.Handler) http.Handler {
	token := s.cfg.Metrics.BearerToken.Value()
	if token == "" {
		return next
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(strings.TrimSpace(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
