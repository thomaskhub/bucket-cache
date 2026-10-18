package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestIndexAndHeaders(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	html := string(body)
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("index: %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	for k, want := range map[string]string{
		"Content-Security-Policy": CSP,
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := res.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if strings.Contains(CSP, "unsafe-") || !strings.Contains(CSP, "frame-ancestors 'none'") {
		t.Errorf("CSP too weak: %s", CSP)
	}
	// Every page file is mounted with its script, and there is no inline
	// script or style (the CSP would block it).
	for _, id := range []string{"dashboard", "tokens", "apikeys", "buckets", "repos", "users"} {
		if !strings.Contains(html, `x-data="page_`+id+`"`) || !strings.Contains(html, `src="/static/js/pages/`+id+`.js"`) {
			t.Errorf("page %s not assembled", id)
		}
	}
	if regexp.MustCompile(`<script(\s+defer)?>|<script>|<style|\sstyle=|\son[a-z]+=`).MatchString(html) {
		t.Error("inline script, style or event handler in index.html")
	}
	if !strings.Contains(html, `id="http-warning"`) {
		t.Error("no plain-HTTP warning banner")
	}

	for path, ctype := range map[string]string{
		"/static/js/app.js":                   "text/javascript",
		"/static/vendor/alpine-csp.min.js":    "text/javascript",
		"/static/css/app.css":                 "text/css",
		"/static/img/icon.svg":                "image/svg+xml",
		"/static/vendor/LICENSE-alpinejs.txt": "",
	} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), ctype) || res.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("%s: %d %s", path, res.StatusCode, res.Header.Get("Content-Type"))
		}
	}
	for _, path := range []string{"/static/", "/static/js/", "/static/../ui.go", "/nope"} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Errorf("%s: %d, want 404", path, res.StatusCode)
		}
	}
}
