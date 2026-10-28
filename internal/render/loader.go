package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"
)

// Typed loader errors. Callers map these to HTTP status codes, so they are
// wrapped (never replaced) to keep errors.Is working through context.
var (
	ErrInvalidName     = errors.New("invalid name")
	ErrUnknownUser     = errors.New("unknown user")
	ErrUnknownMode     = errors.New("unknown mode")
	ErrModeNotAllowed  = errors.New("mode not allowed")
	ErrUnknownTemplate = errors.New("unknown template")
	ErrInvalidConfig   = errors.New("invalid config")
)

// Defaults applied when a user file omits the corresponding field.
const (
	defaultTemplate = "base"
	defaultMode     = "tun"
)

// maxConfigSize bounds every file the loader reads. Config fragments are small
// JSON documents; anything larger is treated as a configuration error rather
// than read into memory.
const maxConfigSize = 4 << 20 // 4 MiB

// configNamePattern is the only shape accepted for a user or mode name. It
// forbids path separators, leading dots, and "..", so a name can never escape
// its directory even before os.Root's own confinement applies.
var configNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Config is the fully resolved input for one render: a user identity, the mode
// selected for this request, and the raw base template. Render consumes these
// three values and does not touch the filesystem itself.
type Config struct {
	User     User
	Mode     Mode
	Template []byte
}

// Loader reads per-user, per-mode, and template files from a single config
// root. Every path is opened through the *os.Root, so names that try to escape
// the root (including via symlinks) are rejected by the kernel-level
// confinement rather than by string inspection alone.
type Loader struct {
	root *os.Root
}

// NewLoader opens configRoot as a confined filesystem root. The directory must
// exist. The caller owns the returned Loader and should Close it.
func NewLoader(configRoot string) (*Loader, error) {
	root, err := os.OpenRoot(configRoot)
	if err != nil {
		return nil, fmt.Errorf("open config root %q: %w", configRoot, err)
	}

	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("stat config root %q: %w", configRoot, err)
	}
	if !info.IsDir() {
		root.Close()
		return nil, fmt.Errorf("config root %q: %w: not a directory", configRoot, ErrInvalidConfig)
	}

	return &Loader{root: root}, nil
}

// Close releases the config root. It is safe to call once; after Close the
// loader refuses further reads instead of panicking.
func (l *Loader) Close() error {
	if l == nil || l.root == nil {
		return nil
	}
	err := l.root.Close()
	l.root = nil
	if err != nil {
		return fmt.Errorf("close config root: %w", err)
	}
	return nil
}

// LoadUser reads and validates users/<name>.json.
func (l *Loader) LoadUser(name string) (User, error) {
	if err := validateConfigName(name); err != nil {
		return User{}, fmt.Errorf("user %q: %w", name, err)
	}

	data, err := l.read("users/" + name + ".json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return User{}, fmt.Errorf("user %q: %w", name, ErrUnknownUser)
		}
		return User{}, fmt.Errorf("user %q: %w: %v", name, ErrInvalidConfig, err)
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return User{}, fmt.Errorf("user %q: %w: %v", name, ErrInvalidConfig, err)
	}
	if strings.TrimSpace(user.UUID) == "" {
		return User{}, fmt.Errorf("user %q: %w: empty uuid", name, ErrInvalidConfig)
	}

	return user, nil
}

// LoadMode reads and validates modes/<name>.json.
func (l *Loader) LoadMode(name string) (Mode, error) {
	if err := validateConfigName(name); err != nil {
		return Mode{}, fmt.Errorf("mode %q: %w", name, err)
	}

	data, err := l.read("modes/" + name + ".json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Mode{}, fmt.Errorf("mode %q: %w", name, ErrUnknownMode)
		}
		return Mode{}, fmt.Errorf("mode %q: %w: %v", name, ErrInvalidConfig, err)
	}

	var mode Mode
	if err := json.Unmarshal(data, &mode); err != nil {
		return Mode{}, fmt.Errorf("mode %q: %w: %v", name, ErrInvalidConfig, err)
	}

	return mode, nil
}

// LoadTemplate reads templates/<profile>.json.tmpl. An empty profile selects
// the default "base" template. It deliberately does not parse the template:
// Render owns parsing, and a text template is not JSON.
func (l *Loader) LoadTemplate(profile string) ([]byte, error) {
	if profile == "" {
		profile = defaultTemplate
	}
	if err := validateConfigName(profile); err != nil {
		return nil, fmt.Errorf("template %q: %w", profile, err)
	}

	data, err := l.read("templates/" + profile + ".json.tmpl")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("template %q: %w", profile, ErrUnknownTemplate)
		}
		return nil, fmt.Errorf("template %q: %w: %v", profile, ErrInvalidConfig, err)
	}
	return data, nil
}

// Load resolves everything needed for one render. The user's template, modes,
// and default mode select the template and mode files; an empty requested mode
// falls back to the user's default. A requested mode outside the user's modes
// is rejected.
func (l *Loader) Load(name, mode string) (Config, error) {
	user, err := l.LoadUser(name)
	if err != nil {
		return Config{}, err
	}

	tmpl, err := l.LoadTemplate(user.Template)
	if err != nil {
		return Config{}, err
	}

	modes := user.Modes
	if len(modes) == 0 {
		modes = []string{defaultMode}
	}
	for _, allowed := range modes {
		if !isKnownMode(allowed) {
			return Config{}, fmt.Errorf("user %q: mode %q: %w", name, allowed, ErrInvalidName)
		}
	}

	selected := user.Default
	if selected == "" {
		selected = modes[0]
	}
	if !containsMode(modes, selected) {
		return Config{}, fmt.Errorf("user %q: default mode %q: %w", name, selected, ErrUnknownMode)
	}

	if mode == "" {
		mode = selected
	}
	if !isKnownMode(mode) {
		return Config{}, fmt.Errorf("mode %q: %w", mode, ErrInvalidName)
	}
	if !containsMode(modes, mode) {
		return Config{}, fmt.Errorf("user %q: mode %q: %w", name, mode, ErrModeNotAllowed)
	}

	m, err := l.LoadMode(mode)
	if err != nil {
		return Config{}, err
	}

	return Config{User: user, Mode: m, Template: tmpl}, nil
}

func isKnownMode(mode string) bool {
	return mode == "tun" || mode == "tproxy"
}

func containsMode(modes []string, mode string) bool {
	for _, m := range modes {
		if m == mode {
			return true
		}
	}
	return false
}

// read opens name relative to the config root and reads at most maxConfigSize
// bytes. os.Root rejects absolute paths, ".." components, and symlink targets
// outside the root; no fallback path is attempted.
func (l *Loader) read(name string) ([]byte, error) {
	if l == nil || l.root == nil {
		return nil, fmt.Errorf("read %q: %w: loader is closed", name, ErrInvalidConfig)
	}

	f, err := l.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigSize {
		return nil, fmt.Errorf("%q: %w: exceeds %d bytes", name, ErrInvalidConfig, maxConfigSize)
	}

	return data, nil
}

// validateConfigName reports whether name is a safe single path component.
// The offending value is included in the error for operator diagnostics.
func validateConfigName(name string) error {
	if !configNamePattern.MatchString(name) {
		return fmt.Errorf("%q: %w", name, ErrInvalidName)
	}
	return nil
}
