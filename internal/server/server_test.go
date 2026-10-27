package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"sing-box-template-renderer/internal/render"
)

const (
	testUUID = "11111111-2222-3333-4444-555555555555"

	// The template has a $hook marker so the tun mode's prefix rule can be
	// inserted; tproxy declares no hooks, so the marker is dropped.
	testTemplate = `{
  "inbounds": [],
  "outbounds": [
    {"type": "trojan", "tag": "proxy", "password": "{{.UUID}}"}
  ],
  "route": {"rules": [{"$hook": "prefix"}]}
}`
)

var etagPattern = regexp.MustCompile(`^"[0-9a-f]{64}"$`)

// fakeLoader returns a fixed Config or error and records the arguments it
// received so header/query plumbing can be asserted.
type fakeLoader struct {
	cfg     render.Config
	err     error
	name    string
	inbound string
	calls   int
}

func (f *fakeLoader) Load(name, inbound string) (render.Config, error) {
	f.name = name
	f.inbound = inbound
	f.calls++
	return f.cfg, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newRouter(loader ConfigLoader) *gin.Engine {
	return New(loader, discardLogger())
}

func testConfig() render.Config {
	return render.Config{
		User:     render.User{UUID: testUUID, AllowTproxy: true},
		Mode:     render.Mode{Inbounds: []any{map[string]any{"type": "tun", "tag": "tun-in"}}},
		Template: []byte(testTemplate),
	}
}

// do issues a request against router and returns the recorder.
func do(router http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// wantETagFor computes the exact validator the server must emit for body.
func wantETagFor(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func assertErrorBody(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("error body is not JSON: %v (body=%q)", err, rec.Body.String())
	}
	if payload.Error != want {
		t.Errorf("error message = %q, want %q", payload.Error, want)
	}
}

func TestRenderGET(t *testing.T) {
	loader := &fakeLoader{cfg: testConfig()}
	router := newRouter(loader)

	rec := do(router, http.MethodGet, "/render?inbound=tproxy", map[string]string{
		"X-Auth-User": "  general  ",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if loader.name != "general" {
		t.Errorf("loader name = %q, want trimmed %q", loader.name, "general")
	}
	if loader.inbound != "tproxy" {
		t.Errorf("loader inbound = %q, want tproxy", loader.inbound)
	}

	body := rec.Body.Bytes()
	if !json.Valid(body) {
		t.Fatalf("body is not valid JSON: %q", body)
	}
	if !strings.Contains(string(body), testUUID) {
		t.Errorf("body does not contain UUID: %s", body)
	}
	if !strings.Contains(string(body), `"tag": "tun-in"`) {
		t.Errorf("body does not contain mode inbound: %s", body)
	}

	etag := rec.Header().Get("ETag")
	if !etagPattern.MatchString(etag) {
		t.Fatalf("ETag = %q, want a quoted lowercase hex sha256", etag)
	}
	if want := wantETagFor(body); etag != want {
		t.Errorf("ETag = %q, want %q", etag, want)
	}
}

func TestRenderGETEmptyInboundIsPassedThrough(t *testing.T) {
	loader := &fakeLoader{cfg: testConfig()}
	router := newRouter(loader)

	rec := do(router, http.MethodGet, "/render", map[string]string{"X-Auth-User": "general"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if loader.inbound != "" {
		t.Errorf("loader inbound = %q, want empty (loader applies the tun default)", loader.inbound)
	}
}

func TestRenderETagAnd304(t *testing.T) {
	router := newRouter(&fakeLoader{cfg: testConfig()})
	headers := map[string]string{"X-Auth-User": "general"}

	first := do(router, http.MethodGet, "/render", headers)
	if first.Code != http.StatusOK {
		t.Fatalf("first GET status = %d, want 200", first.Code)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("first GET has no ETag")
	}

	t.Run("GET matching ETag", func(t *testing.T) {
		rec := do(router, http.MethodGet, "/render", map[string]string{
			"X-Auth-User":   "general",
			"If-None-Match": etag,
		})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want %d (body=%q)", rec.Code, http.StatusNotModified, rec.Body.String())
		}
		if rec.Body.Len() != 0 {
			t.Errorf("304 body = %q, want empty", rec.Body.String())
		}
		if got := rec.Header().Get("ETag"); got != etag {
			t.Errorf("304 ETag = %q, want %q", got, etag)
		}
	})

	t.Run("GET wildcard", func(t *testing.T) {
		rec := do(router, http.MethodGet, "/render", map[string]string{
			"X-Auth-User":   "general",
			"If-None-Match": "*",
		})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", rec.Code)
		}
	})

	t.Run("GET list containing ETag", func(t *testing.T) {
		rec := do(router, http.MethodGet, "/render", map[string]string{
			"X-Auth-User":   "general",
			"If-None-Match": `"nope", ` + etag,
		})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", rec.Code)
		}
	})

	t.Run("GET weak ETag", func(t *testing.T) {
		rec := do(router, http.MethodGet, "/render", map[string]string{
			"X-Auth-User":   "general",
			"If-None-Match": "W/" + etag,
		})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", rec.Code)
		}
	})

	t.Run("HEAD matching ETag", func(t *testing.T) {
		head := do(router, http.MethodHead, "/render", headers)
		if head.Code != http.StatusOK {
			t.Fatalf("HEAD status = %d, want 200", head.Code)
		}
		headETag := head.Header().Get("ETag")
		if headETag == "" {
			t.Fatal("HEAD has no ETag")
		}
		if headETag != etag {
			t.Fatalf("HEAD ETag = %q, want %q", headETag, etag)
		}

		rec := do(router, http.MethodHead, "/render", map[string]string{
			"X-Auth-User":   "general",
			"If-None-Match": headETag,
		})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("HEAD 304 status = %d, want 304", rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("HEAD 304 body = %q, want empty", rec.Body.String())
		}
	})
}

func TestRenderHEAD(t *testing.T) {
	router := newRouter(&fakeLoader{cfg: testConfig()})
	headers := map[string]string{"X-Auth-User": "general"}

	get := do(router, http.MethodGet, "/render", headers)
	if get.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", get.Code)
	}

	rec := do(router, http.MethodHead, "/render", headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD body = %q, want empty", rec.Body.String())
	}
	if got, want := rec.Header().Get("ETag"), get.Header().Get("ETag"); got != want {
		t.Errorf("HEAD ETag = %q, want %q", got, want)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("HEAD Content-Type = %q", got)
	}
}

func TestRenderUnauthorized(t *testing.T) {
	tests := []struct {
		name   string
		method string
		value  string
	}{
		{"GET missing", http.MethodGet, ""},
		{"GET blank", http.MethodGet, "   "},
		{"GET whitespace-only", http.MethodGet, "\t\n "},
		{"HEAD missing", http.MethodHead, ""},
		{"HEAD blank", http.MethodHead, "  \t "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := &fakeLoader{cfg: testConfig()}
			router := newRouter(loader)

			rec := do(router, tt.method, "/render", map[string]string{"X-Auth-User": tt.value})
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body=%q)", rec.Code, rec.Body.String())
			}
			if loader.calls != 0 {
				t.Errorf("loader was called %d times, want 0", loader.calls)
			}
			if tt.method == http.MethodHead {
				if rec.Body.Len() != 0 {
					t.Errorf("HEAD 401 body = %q, want empty", rec.Body.String())
				}
				return
			}
			assertErrorBody(t, rec, "unauthorized")
		})
	}
}

func TestRenderErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "invalid name is 400",
			err:        fmt.Errorf("load: %w", render.ErrInvalidName),
			wantStatus: http.StatusBadRequest,
			wantMsg:    "invalid request",
		},
		{
			name:       "tproxy not allowed is 403",
			err:        fmt.Errorf("load: %w", render.ErrTproxyNotAllowed),
			wantStatus: http.StatusForbidden,
			wantMsg:    "tproxy not allowed",
		},
		{
			name:       "unknown user is 404",
			err:        fmt.Errorf("load: %w", render.ErrUnknownUser),
			wantStatus: http.StatusNotFound,
			wantMsg:    "not found",
		},
		{
			name:       "unknown mode is 404",
			err:        fmt.Errorf("load: %w", render.ErrUnknownMode),
			wantStatus: http.StatusNotFound,
			wantMsg:    "not found",
		},
		{
			name:       "unknown template is 500",
			err:        fmt.Errorf("load: %w", render.ErrUnknownTemplate),
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "render failed",
		},
		{
			name:       "invalid config is 500",
			err:        fmt.Errorf("load: %w", render.ErrInvalidConfig),
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "render failed",
		},
		{
			name:       "unknown error is 500",
			err:        errors.New("/srv/secret/config/users/general.json: boom"),
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "render failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newRouter(&fakeLoader{err: tt.err})

			rec := do(router, http.MethodGet, "/render", map[string]string{"X-Auth-User": "general"})
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body=%q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			assertErrorBody(t, rec, tt.wantMsg)
			if strings.Contains(rec.Body.String(), "/srv/secret") {
				t.Errorf("error body leaks a filesystem path: %q", rec.Body.String())
			}

			head := do(router, http.MethodHead, "/render", map[string]string{"X-Auth-User": "general"})
			if head.Code != tt.wantStatus {
				t.Errorf("HEAD status = %d, want %d", head.Code, tt.wantStatus)
			}
			if head.Body.Len() != 0 {
				t.Errorf("HEAD body = %q, want empty", head.Body.String())
			}
		})
	}
}

func TestRenderTemplateFailure(t *testing.T) {
	cfg := testConfig()
	cfg.Template = []byte(`{"inbounds": [], "bad": "{{.Missing}}"}`)

	router := newRouter(&fakeLoader{cfg: cfg})
	rec := do(router, http.MethodGet, "/render", map[string]string{"X-Auth-User": "general"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body=%q)", rec.Code, rec.Body.String())
	}
	assertErrorBody(t, rec, "render failed")
	if strings.Contains(rec.Body.String(), "template") || strings.Contains(rec.Body.String(), "{{") {
		t.Errorf("error body leaks template details: %q", rec.Body.String())
	}
}

func TestRenderInvalidIfNoneMatchDoesNotPanic(t *testing.T) {
	router := newRouter(&fakeLoader{cfg: testConfig()})

	malformed := []string{
		"garbage",
		`"unterminated`,
		`, , ,`,
		"W/",
		"*garbage",
		`","`,
	}

	for _, value := range malformed {
		t.Run(value, func(t *testing.T) {
			rec := do(router, http.MethodGet, "/render", map[string]string{
				"X-Auth-User":   "general",
				"If-None-Match": value,
			})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	router := newRouter(&fakeLoader{cfg: testConfig()})

	t.Run("GET", func(t *testing.T) {
		rec := do(router, http.MethodGet, "/healthz", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := rec.Body.String(); got != "ok\n" {
			t.Errorf("body = %q, want %q", got, "ok\n")
		}
	})

	t.Run("HEAD", func(t *testing.T) {
		rec := do(router, http.MethodHead, "/healthz", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("body = %q, want empty", rec.Body.String())
		}
	})
}

// TestRealLoaderIntegration drives the handler with a real *render.Loader and
// temp fixtures, exercising the full loader -> render -> HTTP path.
func TestRealLoaderIntegration(t *testing.T) {
	root := t.TempDir()
	fixtures := map[string]string{
		"users/general.json":       `{"uuid":"` + testUUID + `","allow_tproxy":true}`,
		"users/alice.json":         `{"uuid":"22222222-3333-4444-5555-666666666666"}`,
		"modes/tun.json":           `{"inbounds":[{"type":"tun","tag":"tun-in"}],"route":{"rules":{"prefix":[{"type":"field","tag":"prefix"}]}}}`,
		"modes/tproxy.json":        `{"inbounds":[{"type":"tproxy","tag":"tproxy-in"}]}`,
		"templates/base.json.tmpl": testTemplate,
	}
	for rel, content := range fixtures {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	loader, err := render.NewLoader(root)
	if err != nil {
		t.Fatalf("render.NewLoader(%q): %v", root, err)
	}
	t.Cleanup(func() {
		if err := loader.Close(); err != nil {
			t.Errorf("loader.Close(): %v", err)
		}
	})

	router := newRouter(loader)

	tests := []struct {
		name        string
		user        string
		query       string
		wantStatus  int
		wantContain string
	}{
		{"general tun", "general", "?inbound=tun", http.StatusOK, `"tag": "tun-in"`},
		{"general default tun", "general", "", http.StatusOK, `"tag": "tun-in"`},
		{"general tproxy", "general", "?inbound=tproxy", http.StatusOK, `"tag": "tproxy-in"`},
		{"alice tun", "alice", "?inbound=tun", http.StatusOK, `"tag": "tun-in"`},
		{"alice tproxy forbidden", "alice", "?inbound=tproxy", http.StatusForbidden, ""},
		{"unknown user", "nobody", "?inbound=tun", http.StatusNotFound, ""},
		{"invalid inbound", "general", "?inbound=bogus", http.StatusBadRequest, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(router, http.MethodGet, "/render"+tt.query, map[string]string{"X-Auth-User": tt.user})
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body=%q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus == http.StatusOK {
				if !json.Valid(rec.Body.Bytes()) {
					t.Errorf("body is not valid JSON: %q", rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), tt.wantContain) {
					t.Errorf("body missing %q: %s", tt.wantContain, rec.Body.String())
				}
				if strings.Contains(rec.Body.String(), "$hook") {
					t.Errorf("body still contains a $hook marker: %s", rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), testUUID) && tt.user == "general" {
					t.Errorf("body does not contain general's UUID: %s", rec.Body.String())
				}
				if got := rec.Header().Get("ETag"); !etagPattern.MatchString(got) {
					t.Errorf("ETag = %q, want quoted sha256", got)
				}
			}
			if tt.wantStatus == http.StatusForbidden {
				assertErrorBody(t, rec, "tproxy not allowed")
			}
		})
	}
}

// TestNewNilLogger checks New accepts a nil logger without panicking.
func TestNewNilLogger(t *testing.T) {
	router := New(&fakeLoader{cfg: testConfig()}, nil)
	rec := do(router, http.MethodGet, "/healthz", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
