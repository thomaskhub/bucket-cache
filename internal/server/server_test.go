package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomaskhub/bucket-cache/internal/config"
	"github.com/thomaskhub/bucket-cache/internal/metrics"
)

func testConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	yml := "storage:\n  db_path: " + filepath.Join(dir, "proxy.db") + "\n" + extra
	c, err := config.Parse([]byte(yml), func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestHealthAndReady(t *testing.T) {
	s := New(testConfig(t, ""), quietLog(), metrics.NewRegistry())

	rec := httptest.NewRecorder()
	s.Admin.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || rec.Body.String() != "ok\n" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.Admin.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	var body struct{ Ready bool }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 200 || !body.Ready {
		t.Fatalf("readyz = %d %s", rec.Code, rec.Body.String())
	}
}

func TestReadyFailsWhenDirMissing(t *testing.T) {
	c := testConfig(t, "")
	c.Storage.DBPath = "/nonexistent-dir/proxy.db"
	s := New(c, quietLog(), metrics.NewRegistry())
	rec := httptest.NewRecorder()
	s.Admin.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), ".readyz-") {
		t.Errorf("readyz leaks temp path: %s", rec.Body.String())
	}
}

func TestMetricsBearerToken(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(testConfig(t, "metrics:\n  bearer_token: { file: "+tok+" }\n"), quietLog(), metrics.NewRegistry())

	rec := httptest.NewRecorder()
	s.Admin.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 401 {
		t.Fatalf("metrics without token = %d, want 401", rec.Code)
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	s.Admin.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "yproxy_build_info") {
		t.Fatalf("metrics with token = %d, body missing build_info", rec.Code)
	}
}

func TestMetricsNotOnDataListener(t *testing.T) {
	s := New(testConfig(t, ""), quietLog(), metrics.NewRegistry())
	rec := httptest.NewRecorder()
	s.Data.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 404 {
		t.Fatalf("data /metrics = %d, want 404", rec.Code)
	}
}

func freePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestRunAndGracefulShutdown(t *testing.T) {
	c := testConfig(t, "")
	c.Server.DataListen, c.Server.AdminListen = freePort(t), freePort(t)
	s := New(c, quietLog(), metrics.NewRegistry())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	var resp *http.Response
	var err error
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + c.Server.AdminListen + "/healthz")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server didn't start: %v", err)
	}
	resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timed out")
	}
}
