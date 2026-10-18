// Command yproxy is an S3 and git caching proxy for Yocto builds.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/thomaskhub/bucket-cache/internal/api"
	"github.com/thomaskhub/bucket-cache/internal/auth"
	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/gitmirror"
	"github.com/thomaskhub/bucket-cache/internal/metrics"
	"github.com/thomaskhub/bucket-cache/internal/s3proxy"
	"github.com/thomaskhub/bucket-cache/internal/server"
	"github.com/thomaskhub/bucket-cache/internal/store"
	"github.com/thomaskhub/bucket-cache/internal/ui"
	"github.com/thomaskhub/bucket-cache/internal/version"
)

const usage = `Usage: yproxy <command> [flags]

Commands:
  serve          run the proxy
  config check   validate the config and its secret files without starting
  healthcheck    exit 0 if the local admin listener answers /healthz (for Docker)
  user           manage web UI users: create, reset-password, reset-totp, list
  version        print the version

Flags:
  --config PATH  config file (default $PROXY_CONFIG or /etc/proxy/config.yaml)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	if cmd == "user" {
		return userCommand(rest, stdout, stderr)
	}
	if cmd == "config" {
		if len(rest) == 0 || rest[0] != "check" {
			fmt.Fprint(stderr, usage)
			return 2
		}
		cmd, rest = "config check", rest[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	if err := fs.Parse(rest); err != nil {
		return 2
	}

	switch cmd {
	case "version":
		fmt.Fprintf(stdout, "yproxy %s (%s)\n", version.Version, version.Commit)
		return 0
	case "config check":
		if _, err := config.Load(*cfgPath); err != nil {
			fmt.Fprintf(stderr, "config %s is invalid:\n%v\n", *cfgPath, err)
			return 1
		}
		fmt.Fprintf(stdout, "config %s is valid\n", *cfgPath)
		return 0
	case "healthcheck":
		return healthcheck(*cfgPath, stderr)
	case "serve":
		return serve(*cfgPath, stderr)
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

func defaultConfigPath() string {
	if p := os.Getenv("PROXY_CONFIG"); p != "" {
		return p
	}
	return config.DefaultPath
}

func newLogger(level string, w io.Writer) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

func serve(cfgPath string, stderr io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config %s is invalid:\n%v\n", cfgPath, err)
		return 1
	}
	log := newLogger(cfg.Log.Level, os.Stdout)
	log.Info("starting yproxy", "version", version.Version, "buckets", len(cfg.Buckets))
	if !cfg.Server.TLS.Enabled() {
		log.Warn("serving plain HTTP: tokens and passwords are sent unencrypted; use TLS or a TLS reverse proxy on untrusted networks")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.Storage.DBPath)
	if err != nil {
		log.Error("opening database failed", "path", cfg.Storage.DBPath, "error", err.Error())
		return 1
	}
	defer st.Close()

	userSvc, err := setupUsers(ctx, cfg, st, log)
	if err != nil {
		log.Error("setting up users failed", "error", err.Error())
		return 1
	}
	webUI, err := ui.New()
	if err != nil {
		log.Error("loading the web UI failed", "error", err.Error())
		return 1
	}

	reg := metrics.NewRegistry()
	authn := auth.New(st, log, cfg.Auth.BootstrapAdminKey.Value(), cfg.Auth.ValidationCacheTTL.D())
	var mirrors *gitmirror.Manager
	if cfg.Git != nil {
		mirrors, err = gitmirror.New(ctx, cfg.Git, gitmirror.Options{Logger: log, Registerer: reg, PublicBaseURL: cfg.Server.PublicBaseURL})
		if err != nil {
			log.Error("starting the git mirror failed", "error", err.Error())
			return 1
		}
	}
	maintCtx, stopMaint := context.WithCancel(context.Background())
	maintDone := make(chan struct{})
	go func() { authn.RunMaintenance(maintCtx, 10*time.Second); close(maintDone) }()
	go reportActiveTokens(ctx, st, reg, log)
	go userSvc.RunMaintenance(ctx, 10*time.Minute)

	backends := map[string]s3proxy.Backend{}
	for _, b := range cfg.Buckets {
		backends[b.Alias] = s3proxy.NewS3Backend(b)
	}
	objects := s3proxy.NewHandler(backends, authn, log, reg, cfg.Log.Access)

	opts := []server.Option{server.WithPing(st.Ping)}
	gitDone := make(chan struct{})
	if mirrors != nil {
		// The git route goes first: the object route also claims /t/{token}/...
		opts = append(opts, server.WithRoute(mirrors.NewHandler(authn, cfg.Log.Access)),
			server.WithReadyDetail("git", mirrors.ReadyDetails))
		go func() { mirrors.Run(ctx); close(gitDone) }()
	} else {
		close(gitDone)
	}
	opts = append(opts, server.WithRoute(objects))

	srv := server.New(cfg, log, reg, opts...)
	apiSrv := api.New(cfg, st, authn, backends, log).WithUsers(userSvc)
	apiSrv.Register(srv.Admin)
	webUI.Register(srv.Admin)
	if mirrors != nil {
		mirrors.RegisterAPI(srv.Admin, apiSrv.Authenticated, apiSrv.AdminOnly)
	}

	runErr := srv.Run(ctx)
	stopMaint()
	<-maintDone // flush token usage before the database closes
	<-gitDone
	if runErr != nil {
		log.Error("server stopped", "error", runErr.Error())
		return 1
	}
	return 0
}

// reportActiveTokens updates the active-token gauge every 30 seconds.
func reportActiveTokens(ctx context.Context, st *store.Store, reg prometheus.Registerer, log *slog.Logger) {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: metrics.Namespace, Name: "tokens_active",
		Help: "Tokens that are neither expired nor revoked, by kind."}, []string{"kind"})
	reg.MustRegister(g)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		counts, err := st.CountActiveTokens(ctx, time.Now())
		if err == nil {
			g.Reset()
			for k, n := range counts {
				g.WithLabelValues(k).Set(float64(n))
			}
		} else if ctx.Err() == nil {
			log.Warn("counting active tokens failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// healthcheck lets the container image check itself without curl or a shell.
func healthcheck(cfgPath string, stderr io.Writer) int {
	addr := ":8081"
	tlsOn := false
	if cfg, err := config.Load(cfgPath); err == nil {
		addr, tlsOn = cfg.Server.AdminListen, cfg.Server.TLS.Enabled()
	} else if v := os.Getenv("PROXY_ADMIN_LISTEN"); v != "" {
		addr = v
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintf(stderr, "bad admin address %q\n", addr)
		return 1
	}
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if tlsOn {
		scheme = "https"
		// The certificate is for the public name, not 127.0.0.1.
		client.Transport = insecureLoopbackTransport()
	}
	resp, err := client.Get(scheme + "://127.0.0.1:" + port + "/healthz") //nolint:gosec // G704: fixed loopback URL
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != "ok" {
		fmt.Fprintf(stderr, "healthcheck failed: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
