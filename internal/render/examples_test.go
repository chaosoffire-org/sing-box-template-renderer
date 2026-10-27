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

	tmpl, err := loader.LoadTemplate()
	if err != nil {
		t.Fatalf("LoadTemplate(): %v", err)
	}
	if !strings.Contains(string(tmpl), "{{.UUID}}") {
		t.Fatalf("base template does not contain a {{.UUID}} placeholder")
	}
	if !strings.Contains(string(tmpl), "{{.Name}}") {
		t.Fatalf("base template does not contain a {{.Name}} placeholder")
	}

	// wantPrefixRule records whether the tun mode's resolve rule (injected via
	// the template's {"$hook":"prefix"} marker) must appear in the output.
	cases := []struct {
		user           string
		inbound        string
		wantUUID       string
		wantInboundTag string
		wantPrefixRule bool
	}{
		{"general", "tun", exampleUUIDGeneral, "tun-in", true},
		{"general", "tproxy", exampleUUIDGeneral, "tproxy-in", false},
		{"alice", "tun", exampleUUIDAlice, "tun-in", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.user+"/"+tc.inbound, func(t *testing.T) {
			cfg, err := loader.Load(tc.user, tc.inbound)
			if err != nil {
				t.Fatalf("Load(%q, %q): %v", tc.user, tc.inbound, err)
			}

			out, err := Render(cfg.Template, tc.user, cfg.User, cfg.Mode)
			if err != nil {
				t.Fatalf("Render(%q, %q): %v", tc.user, tc.inbound, err)
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
			if tc.wantPrefixRule && strings.Contains(text, `"$hook"`) {
				t.Errorf("tun output contains a $hook marker:\n%s", out)
			}
		})
	}

	t.Run("alice/tproxy is rejected", func(t *testing.T) {
		if _, err := loader.Load("alice", "tproxy"); !errors.Is(err, ErrTproxyNotAllowed) {
			t.Fatalf("Load(alice, tproxy) error = %v, want ErrTproxyNotAllowed", err)
		}
	})
}
