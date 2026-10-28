package render

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testUUIDGeneral = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testUUIDAlice   = "11111111-2222-3333-4444-555555555555"
)

const testBaseTemplate = `{
  "inbounds": [],
  "log": {"level": "info"},
  "outbounds": [
    {"type": "trojan", "tag": "proxy", "password": "{{.UUID}}"}
  ]
}`

const testOwnerTemplate = `{
  "inbounds": [],
  "log": {"level": "warn"},
  "http_clients": [{"tag": "default"}],
  "outbounds": [
    {"type": "trojan", "tag": "proxy", "password": "{{.UUID}}"}
  ]
}`

// writeFixture writes rel under root, creating parent directories as needed.
func writeFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeFixtureRoot creates the complete fixture tree shared by the loader
// tests: two users, both modes, and the base template.
func writeFixtureRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "users/general.json", `{"template":"owner","uuid":"`+testUUIDGeneral+`","modes":["tproxy","tun"],"default":"tun"}`)
	writeFixture(t, root, "users/alice.json", `{"uuid":"`+testUUIDAlice+`"}`)
	writeFixture(t, root, "modes/tun.json", `{
		"inbounds": [{"type": "tun", "tag": "tun-in"}],
		"route": {"rules": {"prefix": [{"type": "field", "tag": "prefix"}]}}
	}`)
	writeFixture(t, root, "modes/tproxy.json", `{"inbounds": [{"type": "tproxy", "tag": "tproxy-in"}]}`)
	writeFixture(t, root, "templates/base.json.tmpl", testBaseTemplate)
	writeFixture(t, root, "templates/owner.json.tmpl", testOwnerTemplate)
	return root
}

func newLoader(t *testing.T, root string) *Loader {
	t.Helper()
	l, err := NewLoader(root)
	if err != nil {
		t.Fatalf("NewLoader(%q): %v", root, err)
	}
	return l
}

// inboundTag returns the first inbound tag so mode resolution can be asserted
// without depending on map ordering.
func inboundTag(t *testing.T, mode Mode) string {
	t.Helper()
	if len(mode.Inbounds) == 0 {
		t.Fatalf("mode has no inbounds: %#v", mode.Inbounds)
	}
	obj, ok := mode.Inbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("first inbound is not an object: %#v", mode.Inbounds[0])
	}
	tag, ok := obj["tag"].(string)
	if !ok {
		t.Fatalf("first inbound has no string tag: %#v", obj)
	}
	return tag
}

func TestLoad(t *testing.T) {
	l := newLoader(t, writeFixtureRoot(t))
	defer func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	t.Run("general default is tun with owner template", func(t *testing.T) {
		cfg, err := l.Load("general", "")
		if err != nil {
			t.Fatalf("Load(): %v", err)
		}
		if cfg.User.UUID != testUUIDGeneral {
			t.Errorf("user uuid = %q, want %q", cfg.User.UUID, testUUIDGeneral)
		}
		if got := inboundTag(t, cfg.Mode); got != "tun-in" {
			t.Errorf("mode inbound = %q, want tun-in", got)
		}
		if rules := cfg.Mode.Route.Rules["prefix"]; len(rules) != 1 {
			t.Errorf("mode prefix rules = %d, want 1", len(rules))
		}
		if !bytes.Equal(cfg.Template, []byte(testOwnerTemplate)) {
			t.Errorf("template bytes = %q, want owner template", cfg.Template)
		}
	})

	t.Run("general tproxy selects tproxy mode", func(t *testing.T) {
		cfg, err := l.Load("general", "tproxy")
		if err != nil {
			t.Fatalf("Load(): %v", err)
		}
		if got := inboundTag(t, cfg.Mode); got != "tproxy-in" {
			t.Errorf("mode inbound = %q, want tproxy-in", got)
		}
	})

	t.Run("alice default is tun with base template", func(t *testing.T) {
		cfg, err := l.Load("alice", "")
		if err != nil {
			t.Fatalf("Load(): %v", err)
		}
		if cfg.User.UUID != testUUIDAlice {
			t.Errorf("user uuid = %q, want %q", cfg.User.UUID, testUUIDAlice)
		}
		if got := inboundTag(t, cfg.Mode); got != "tun-in" {
			t.Errorf("mode inbound = %q, want tun-in", got)
		}
		if !bytes.Equal(cfg.Template, []byte(testBaseTemplate)) {
			t.Errorf("template bytes = %q, want base template", cfg.Template)
		}
	})

	t.Run("alice tproxy is not allowed", func(t *testing.T) {
		if _, err := l.Load("alice", "tproxy"); !errors.Is(err, ErrModeNotAllowed) {
			t.Fatalf("Load(alice, tproxy) error = %v, want ErrModeNotAllowed", err)
		}
	})
}

func TestConfine(t *testing.T) {
	l := newLoader(t, writeFixtureRoot(t))
	defer func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	// Every entry must be rejected by name validation before any file is
	// opened: traversal segments, absolute paths, nested paths, hidden names,
	// and dot segments.
	for _, name := range []string{"../evil", "/etc/passwd", "a/b", ".hidden", "..", "evil/../x"} {
		name := name
		t.Run(name, func(t *testing.T) {
			if _, err := l.LoadUser(name); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("LoadUser(%q) error = %v, want ErrInvalidName", name, err)
			}
		})
	}

	t.Run("invalid inbound", func(t *testing.T) {
		if _, err := l.Load("general", "../tproxy"); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Load() error = %v, want ErrInvalidName", err)
		}
	})

	t.Run("symlink escape", func(t *testing.T) {
		base := t.TempDir()
		root := filepath.Join(base, "root")
		writeFixture(t, root, "users/alice.json", `{"uuid":"`+testUUIDAlice+`"}`)
		outside := filepath.Join(base, "outside.json")
		if err := os.WriteFile(outside, []byte(`{"uuid":"99999999-9999-9999-9999-999999999999"}`), 0o644); err != nil {
			t.Fatalf("write outside file: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "users", "evil.json")); err != nil {
			t.Skipf("os.Symlink unsupported: %v", err)
		}

		sl := newLoader(t, root)
		defer func() {
			if err := sl.Close(); err != nil {
				t.Errorf("Close(): %v", err)
			}
		}()

		_, err := sl.LoadUser("evil")
		// Assertion: the symlink target lives outside the config root, so the
		// load must fail with errors.Is(err, ErrInvalidName), or with any other
		// non-nil error that is NOT ErrUnknownUser. The target exists, so
		// reporting "unknown user" would mean a confinement failure was masked
		// as a missing file.
		if err == nil {
			t.Fatalf("LoadUser(%q) succeeded through a symlink escape", "evil")
		}
		if errors.Is(err, ErrUnknownUser) {
			t.Fatalf("symlink escape reported as unknown user: %v", err)
		}
		if !errors.Is(err, ErrInvalidName) {
			t.Logf("symlink escape rejected with non-ErrInvalidName confinement error: %v", err)
		}
	})
}

func TestTproxy(t *testing.T) {
	l := newLoader(t, writeFixtureRoot(t))
	defer func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()

	t.Run("user without tproxy mode is denied", func(t *testing.T) {
		if _, err := l.Load("alice", "tproxy"); !errors.Is(err, ErrModeNotAllowed) {
			t.Fatalf("Load(alice, tproxy) error = %v, want ErrModeNotAllowed", err)
		}
	})

	t.Run("user with tproxy mode succeeds", func(t *testing.T) {
		if _, err := l.Load("general", "tproxy"); err != nil {
			t.Fatalf("Load(general, tproxy): %v", err)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		if _, err := l.Load("nobody", "tun"); !errors.Is(err, ErrUnknownUser) {
			t.Fatalf("Load(nobody, tun) error = %v, want ErrUnknownUser", err)
		}
	})

	t.Run("unknown mode", func(t *testing.T) {
		root := writeFixtureRoot(t)
		if err := os.Remove(filepath.Join(root, "modes", "tproxy.json")); err != nil {
			t.Fatalf("remove tproxy mode: %v", err)
		}
		ml := newLoader(t, root)
		defer func() {
			if err := ml.Close(); err != nil {
				t.Errorf("Close(): %v", err)
			}
		}()

		if _, err := ml.Load("general", "tproxy"); !errors.Is(err, ErrUnknownMode) {
			t.Fatalf("Load(general, tproxy) error = %v, want ErrUnknownMode", err)
		}
	})

	t.Run("missing template", func(t *testing.T) {
		root := writeFixtureRoot(t)
		if err := os.Remove(filepath.Join(root, "templates", "owner.json.tmpl")); err != nil {
			t.Fatalf("remove template: %v", err)
		}
		ml := newLoader(t, root)
		defer func() {
			if err := ml.Close(); err != nil {
				t.Errorf("Close(): %v", err)
			}
		}()

		if _, err := ml.Load("general", "tun"); !errors.Is(err, ErrUnknownTemplate) {
			t.Fatalf("Load(general, tun) error = %v, want ErrUnknownTemplate", err)
		}
	})
}

// newUserLoader builds a loader whose only user is u.json, with the base
// template and both known modes present.
func newUserLoader(t *testing.T, userJSON string) *Loader {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "users/u.json", userJSON)
	writeFixture(t, root, "templates/base.json.tmpl", testBaseTemplate)
	writeFixture(t, root, "modes/tun.json", `{"inbounds": [{"type": "tun", "tag": "tun-in"}]}`)
	writeFixture(t, root, "modes/tproxy.json", `{"inbounds": [{"type": "tproxy", "tag": "tproxy-in"}]}`)
	l := newLoader(t, root)
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
	return l
}

func TestUserModeSelection(t *testing.T) {
	t.Run("empty default selects modes[0]", func(t *testing.T) {
		l := newUserLoader(t, `{"uuid":"`+testUUIDGeneral+`","modes":["tproxy","tun"]}`)
		cfg, err := l.Load("u", "")
		if err != nil {
			t.Fatalf("Load(): %v", err)
		}
		if got := inboundTag(t, cfg.Mode); got != "tproxy-in" {
			t.Errorf("mode inbound = %q, want tproxy-in", got)
		}
	})

	t.Run("default outside modes is rejected", func(t *testing.T) {
		l := newUserLoader(t, `{"uuid":"`+testUUIDGeneral+`","modes":["tun"],"default":"bogus"}`)
		if _, err := l.Load("u", ""); !errors.Is(err, ErrUnknownMode) {
			t.Fatalf("Load() error = %v, want ErrUnknownMode", err)
		}
	})

	t.Run("unknown requested mode is invalid", func(t *testing.T) {
		l := newUserLoader(t, `{"uuid":"`+testUUIDGeneral+`","modes":["tun"]}`)
		if _, err := l.Load("u", "bogus"); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Load() error = %v, want ErrInvalidName", err)
		}
	})

	t.Run("mode outside user modes is not allowed", func(t *testing.T) {
		l := newUserLoader(t, `{"uuid":"`+testUUIDGeneral+`","modes":["tun"]}`)
		if _, err := l.Load("u", "tproxy"); !errors.Is(err, ErrModeNotAllowed) {
			t.Fatalf("Load() error = %v, want ErrModeNotAllowed", err)
		}
	})

	t.Run("invalid modes entry is rejected", func(t *testing.T) {
		l := newUserLoader(t, `{"uuid":"`+testUUIDGeneral+`","modes":["tun","socks"]}`)
		if _, err := l.Load("u", ""); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Load() error = %v, want ErrInvalidName", err)
		}
	})
}

func TestTemplateSelection(t *testing.T) {
	t.Run("empty template selects base", func(t *testing.T) {
		root := writeFixtureRoot(t)
		l := newLoader(t, root)
		defer func() { _ = l.Close() }()

		if _, err := l.LoadTemplate(""); err != nil {
			t.Fatalf("LoadTemplate(\"\"): %v", err)
		}
		cfg, err := l.Load("alice", "tun")
		if err != nil {
			t.Fatalf("Load(): %v", err)
		}
		if !bytes.Equal(cfg.Template, []byte(testBaseTemplate)) {
			t.Errorf("template bytes = %q, want base template", cfg.Template)
		}
	})

	t.Run("missing owner file is unknown", func(t *testing.T) {
		root := writeFixtureRoot(t)
		if err := os.Remove(filepath.Join(root, "templates", "owner.json.tmpl")); err != nil {
			t.Fatalf("remove owner template: %v", err)
		}
		l := newLoader(t, root)
		defer func() { _ = l.Close() }()

		if _, err := l.Load("general", "tun"); !errors.Is(err, ErrUnknownTemplate) {
			t.Fatalf("Load() error = %v, want ErrUnknownTemplate", err)
		}
	})

	t.Run("invalid template name is rejected", func(t *testing.T) {
		l := newUserLoader(t, `{"uuid":"`+testUUIDGeneral+`","template":"../evil","modes":["tun"]}`)
		if _, err := l.Load("u", ""); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Load() error = %v, want ErrInvalidName", err)
		}
	})
}

// TestInvalidConfig covers malformed user/mode files and the empty-UUID
// invariant that would otherwise render a config with a blank credential.
func TestInvalidConfig(t *testing.T) {
	t.Run("empty uuid", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "users/empty.json", `{"uuid":""}`)
		l := newLoader(t, root)
		defer func() { _ = l.Close() }()

		if _, err := l.LoadUser("empty"); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("LoadUser(empty) error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("whitespace uuid", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "users/blank.json", `{"uuid":"   "}`)
		l := newLoader(t, root)
		defer func() { _ = l.Close() }()

		if _, err := l.LoadUser("blank"); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("LoadUser(blank) error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("malformed user json", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "users/broken.json", `{"uuid":`)
		l := newLoader(t, root)
		defer func() { _ = l.Close() }()

		if _, err := l.LoadUser("broken"); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("LoadUser(broken) error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("malformed mode json", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "modes/broken.json", `{`)
		l := newLoader(t, root)
		defer func() { _ = l.Close() }()

		if _, err := l.LoadMode("broken"); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("LoadMode(broken) error = %v, want ErrInvalidConfig", err)
		}
	})

	t.Run("oversized user file", func(t *testing.T) {
		root := t.TempDir()
		writeFixture(t, root, "users/huge.json", strings.Repeat("a", maxConfigSize+1))
		l := newLoader(t, root)
		defer func() { _ = l.Close() }()

		if _, err := l.LoadUser("huge"); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("LoadUser(huge) error = %v, want ErrInvalidConfig", err)
		}
	})
}

// TestNewLoaderRejectsFile ensures the loader only accepts a directory root.
func TestNewLoaderRejectsFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "not-a-dir")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := NewLoader(path); err == nil {
		t.Fatalf("NewLoader(%q) succeeded, want error", path)
	}
	if _, err := NewLoader(filepath.Join(root, "missing")); err == nil {
		t.Fatalf("NewLoader(missing) succeeded, want error")
	}
}
