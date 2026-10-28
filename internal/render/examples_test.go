package render

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Placeholder UUIDs used by the sanitized examples/ fixtures. They are
// deliberately sequential and non-secret so a rendered example can never be
// mistaken for a real credential.
const (
	exampleUUIDGeneral = "00000000-0000-0000-0000-000000000001"
	exampleUUIDAlice   = "00000000-0000-0000-0000-000000000002"
)

// TestExamples renders every sanitized example user/mode pair through the real
// loader and renderer. It is the guard that keeps examples/ a working,
// secret-free starting point for self-hosters (and the fixture set used by the
// server's manual QA).
func TestExamples(t *testing.T) {
	// examples/ lives at the module root; this test runs in internal/render.
	loader, err := NewLoader(filepath.Join("..", "..", "examples"))
	if err != nil {
		t.Fatalf("NewLoader(examples): %v", err)
	}
	defer func() {
		if err := loader.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	base, err := loader.LoadTemplate("")
	if err != nil {
		t.Fatalf("LoadTemplate(base): %v", err)
	}
	for _, placeholder := range []string{"{{.UUID}}", "{{.Name}}"} {
		if !strings.Contains(string(base), placeholder) {
			t.Errorf("base template does not contain %s", placeholder)
		}
	}
	if strings.Contains(string(base), `"http_clients"`) {
		t.Errorf("base template unexpectedly contains http_clients")
	}

	owner, err := loader.LoadTemplate("owner")
	if err != nil {
		t.Fatalf("LoadTemplate(owner): %v", err)
	}
	for _, placeholder := range []string{"{{.UUID}}", "{{.Name}}"} {
		if !strings.Contains(string(owner), placeholder) {
			t.Errorf("owner template does not contain %s", placeholder)
		}
	}
	if !strings.Contains(string(owner), `"http_clients"`) {
		t.Errorf("owner template does not contain http_clients")
	}

	cases := []struct {
		user            string
		mode            string
		wantUUID        string
		wantInboundTag  string
		wantPrefixRule  bool
		wantHTTPClients bool
	}{
		{"general", "tun", exampleUUIDGeneral, "tun-in", true, true},
		{"general", "tproxy", exampleUUIDGeneral, "tproxy-in", false, true},
		{"alice", "tun", exampleUUIDAlice, "tun-in", true, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.user+"/"+tc.mode, func(t *testing.T) {
			cfg, err := loader.Load(tc.user, tc.mode)
			if err != nil {
				t.Fatalf("Load(%q, %q): %v", tc.user, tc.mode, err)
			}

			out, err := Render(cfg.Template, tc.user, cfg.User, cfg.Mode)
			if err != nil {
				t.Fatalf("Render(%q, %q): %v", tc.user, tc.mode, err)
			}
			if !json.Valid(out) {
				t.Fatalf("rendered output is not valid JSON:\n%s", out)
			}

			text := string(out)
			if strings.Contains(text, "$hook") {
				t.Errorf("rendered output still contains a $hook marker:\n%s", out)
			}
			if !strings.Contains(text, tc.wantUUID) {
				t.Errorf("rendered output is missing UUID %q:\n%s", tc.wantUUID, out)
			}
			if want := `"tag": "` + tc.wantInboundTag + `"`; !strings.Contains(text, want) {
				t.Errorf("rendered output is missing inbound %s:\n%s", want, out)
			}
			if want := `"server_name": "` + tc.user + `.example.com"`; !strings.Contains(text, want) {
				t.Errorf("rendered output is missing substituted %s:\n%s", want, out)
			}

			hasPrefixRule := strings.Contains(text, `"action": "resolve"`) &&
				strings.Contains(text, `"server": "local"`)
			if hasPrefixRule != tc.wantPrefixRule {
				t.Errorf("prefix rule present = %t, want %t:\n%s", hasPrefixRule, tc.wantPrefixRule, out)
			}
			hasHTTPClients := strings.Contains(text, `"http_clients"`)
			if hasHTTPClients != tc.wantHTTPClients {
				t.Errorf("http_clients present = %t, want %t:\n%s", hasHTTPClients, tc.wantHTTPClients, out)
			}
		})
	}

	t.Run("alice/tproxy is not allowed", func(t *testing.T) {
		if _, err := loader.Load("alice", "tproxy"); !errors.Is(err, ErrModeNotAllowed) {
			t.Fatalf("Load(alice, tproxy) error = %v, want ErrModeNotAllowed", err)
		}
	})
}
