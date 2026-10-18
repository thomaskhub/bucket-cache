// Package ui serves the embedded web UI on the admin listener (FR-60, FR-63).
//
// The UI is a single page built from Alpine.js (CSP build) and a prebuilt
// Tailwind stylesheet, all embedded so it works without network access. It
// talks only to /api/v1 (FR-62).
//
// Adding a page needs no change here: drop static/pages/<id>.html (the
// page's markup) and static/js/pages/<id>.js (which calls YP.page to
// register the component and its nav entry). index.html is assembled from
// those files at startup.
package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
)

//go:embed static
var staticFS embed.FS

//go:embed layout.html
var layoutHTML string

// CSP allows only our own scripts and styles (SEC-22). Alpine's CSP build
// evaluates directives without eval, so no 'unsafe-eval' or inline script
// is needed. The TOTP QR code is a data: image.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"font-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

var pageID = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

type page struct {
	ID     string
	Markup template.HTML // trusted: embedded at build time
}

// Handler serves the UI.
type Handler struct {
	index  []byte
	static http.Handler
}

// New assembles index.html from the layout and the page files.
func New() (*Handler, error) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	var pages []page
	files, _ := fs.Glob(sub, "pages/*.html")
	sort.Strings(files)
	for _, f := range files {
		id := strings.TrimSuffix(path.Base(f), ".html")
		if !pageID.MatchString(id) {
			return nil, fmt.Errorf("ui: page file %s: id must match %s", f, pageID)
		}
		b, err := fs.ReadFile(sub, f)
		if err != nil {
			return nil, err
		}
		pages = append(pages, page{ID: id, Markup: template.HTML(b)}) //nolint:gosec // G203: our own embedded markup
	}
	scripts, _ := fs.Glob(sub, "js/pages/*.js")
	sort.Strings(scripts)

	tmpl, err := template.New("layout").Parse(layoutHTML)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]any{"Pages": pages, "PageScripts": scripts}); err != nil {
		return nil, err
	}
	return &Handler{index: buf.Bytes(), static: http.StripPrefix("/static/", http.FileServerFS(sub))}, nil
}

// Register mounts the UI at / and its assets at /static/.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("GET /{$}", SecurityHeaders(http.HandlerFunc(h.serveIndex)))
	mux.Handle("GET /static/", SecurityHeaders(http.HandlerFunc(h.serveStatic)))
}

func (h *Handler) serveIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(h.index)
}

func (h *Handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/") { // no directory listings
		http.NotFound(w, r)
		return
	}
	// Asset names aren't content-hashed, so let the browser revalidate.
	w.Header().Set("Cache-Control", "no-cache")
	h.static.ServeHTTP(w, r)
}

// SecurityHeaders sets the headers every UI response carries (SEC-22).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", CSP)
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
