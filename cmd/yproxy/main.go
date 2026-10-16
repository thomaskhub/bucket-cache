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

	"github.com/thomaskhub/yocto-cache-proxy/internal/config"
	"github.com/thomaskhub/yocto-cache-proxy/internal/metrics"
	"github.com/thomaskhub/yocto-cache-proxy/internal/server"
	"github.com/thomaskhub/yocto-cache-proxy/internal/version"
)

const usage = `Usage: yproxy <command> [flags]

Commands:
  serve          run the proxy
  config check   validate the config and its secret files without starting
  healthcheck    exit 0 if the local admin listener answers /healthz (for Docker)
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
	if err := server.New(cfg, log, metrics.NewRegistry()).Run(ctx); err != nil {
		log.Error("server stopped", "error", err.Error())
		return 1
	}
	return 0
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
	resp, err := client.Get(scheme + "://127.0.0.1:" + port + "/healthz")
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
