package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		in      string
		want    slog.Level
		wantErr bool
	}{
		{in: "debug", want: slog.LevelDebug},
		{in: "INFO", want: slog.LevelInfo},
		{in: "Warn", want: slog.LevelWarn},
		{in: " error ", want: slog.LevelError},
		{in: "", wantErr: true},
		{in: "trace", wantErr: true},
		{in: "verbose", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseLogLevel(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseLogLevel(%q) = %v, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLogLevel(%q) error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("parseLogLevel(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateListen(t *testing.T) {
	tests := []struct {
		addr        string
		allowPublic bool
		wantErr     bool
	}{
		{addr: "127.0.0.1:8080"},
		{addr: "127.42.0.9:8080"},
		{addr: "localhost:8080"},
		{addr: "LOCALHOST:8080"},
		{addr: "[::1]:8080"},
		{addr: "[::1%lo]:8080"},

		{addr: ":8080", wantErr: true},
		{addr: "0.0.0.0:8080", wantErr: true},
		{addr: "[::]:8080", wantErr: true},
		{addr: "192.168.1.10:8080", wantErr: true},
		{addr: "provider.example.com:8080", wantErr: true},
		{addr: "not-an-address", wantErr: true},

		// --allow-public permits anything net.Listen can parse.
		{addr: ":8080", allowPublic: true},
		{addr: "0.0.0.0:8080", allowPublic: true},
		{addr: "[::]:8080", allowPublic: true},
		{addr: "192.168.1.10:8080", allowPublic: true},
	}

	for _, tt := range tests {
		err := validateListen(tt.addr, tt.allowPublic)
		if tt.wantErr {
			if err == nil {
				t.Errorf("validateListen(%q, allowPublic=%v) = nil, want error", tt.addr, tt.allowPublic)
			}
			continue
		}
		if err != nil {
			t.Errorf("validateListen(%q, allowPublic=%v) error: %v", tt.addr, tt.allowPublic, err)
		}
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer

	if err := run([]string{"--help"}, &stdout, &stderr); err != nil {
		t.Fatalf("run(--help) error: %v", err)
	}

	usage := stdout.String() + stderr.String()
	for _, flagName := range []string{
		"--config",
		"--listen",
		"--log-level",
		"--shutdown-timeout",
		"--allow-public",
	} {
		if !strings.Contains(usage, flagName) {
			t.Errorf("usage does not mention %s:\n%s", flagName, usage)
		}
	}
}

func TestRunRejectsNonLoopbackWithoutAllowPublic(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{
		"--config", t.TempDir(),
		"--listen", "0.0.0.0:8080",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run with public listen address and no --allow-public = nil, want error")
	}
	if !strings.Contains(err.Error(), "--allow-public") {
		t.Fatalf("error %q does not mention --allow-public", err)
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error %q does not mention loopback", err)
	}
}

// TestRunAllowPublicAttemptsBind verifies that --allow-public gets past the
// loopback guard and reaches net.Listen. A port is pre-bound on 127.0.0.1 so
// binding the same port on 0.0.0.0 fails immediately instead of serving.
func TestRunAllowPublicAttemptsBind(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occupied.Close()

	_, port, err := net.SplitHostPort(occupied.Addr().String())
	if err != nil {
		t.Fatalf("split occupied address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err = runContext(ctx, []string{
		"--config", t.TempDir(),
		"--listen", "0.0.0.0:" + port,
		"--allow-public",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run with an occupied public port = nil, want a bind error")
	}
	if strings.Contains(err.Error(), "not a loopback") {
		t.Fatalf("--allow-public was rejected by validateListen: %v", err)
	}
	if !strings.Contains(err.Error(), "listen on") {
		t.Fatalf("error %q does not look like a bind failure", err)
	}
}

func TestRunRejectsNonPositiveShutdownTimeout(t *testing.T) {
	var stdout, stderr bytes.Buffer

	err := run([]string{
		"--config", t.TempDir(),
		"--shutdown-timeout", "0s",
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run with --shutdown-timeout 0s = nil, want error")
	}
	if !strings.Contains(err.Error(), "shutdown-timeout") {
		t.Fatalf("error %q does not mention --shutdown-timeout", err)
	}
}

// TestRunShutsDownOnContextCancel exercises the graceful-shutdown path without
// sending signals to the test process.
func TestRunShutsDownOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runContext(ctx, []string{
		"--config", t.TempDir(),
		"--listen", "127.0.0.1:0",
	}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("runContext with a canceled context = %v, want nil", err)
	}
}
