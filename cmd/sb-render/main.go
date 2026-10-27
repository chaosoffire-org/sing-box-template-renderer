// Command sb-render serves rendered sing-box client configurations over HTTP.
//
// It is meant to sit behind nginx: nginx terminates TLS and performs Basic
// Auth, then forwards the authenticated username in X-Auth-User. Because the
// server trusts that header, it refuses to listen on anything but loopback
// unless --allow-public is passed explicitly.
package main

import (
	"context"
	"errors"
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

	"sing-box-template-renderer/internal/render"
	"sing-box-template-renderer/internal/server"
)

// HTTP server timeouts. Requests are small JSON renders, so these stay tight.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "sb-render:", err)
		os.Exit(1)
	}
}

type options struct {
	configDir       string
	listen          string
	logLevel        string
	shutdownTimeout time.Duration
	allowPublic     bool
}

// run parses the command line and runs the server until a termination signal
// arrives. It returns nil for --help and for a clean shutdown.
func run(args []string, stdout, stderr io.Writer) error {
	return runContext(context.Background(), args, stdout, stderr)
}

// runContext is run with an injectable parent context so tests can trigger the
// shutdown path without sending signals to the test process.
func runContext(parent context.Context, args []string, stdout, stderr io.Writer) error {
	opts, err := parseFlags(args, stdout, stderr)
	if err != nil {
		return err
	}
	if opts == nil {
		return nil // --help
	}

	level, err := parseLogLevel(opts.logLevel)
	if err != nil {
		return err
	}
	if opts.shutdownTimeout <= 0 {
		return fmt.Errorf("--shutdown-timeout must be positive, got %s", opts.shutdownTimeout)
	}
	if err := validateListen(opts.listen, opts.allowPublic); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	loader, err := render.NewLoader(opts.configDir)
	if err != nil {
		return fmt.Errorf("open config: %w", err)
	}
	defer func() {
		if err := loader.Close(); err != nil {
			logger.Warn("close config loader", "error", err)
		}
	}()

	engine := server.New(loader, logger)

	listener, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", opts.listen, err)
	}

	srv := &http.Server{
		Handler:           engine,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(listener)
	}()

	logger.Info("sb-render started",
		"addr", listener.Addr().String(),
		"config", opts.configDir,
		"log_level", level.String(),
		"allow_public", opts.allowPublic,
	)

	select {
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	// Restore the default signal behavior so a second signal kills the process
	// immediately instead of being swallowed by this context.
	stop()

	logger.Info("shutting down", "timeout", opts.shutdownTimeout.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), opts.shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		_ = srv.Close()
		<-serveErr
		return fmt.Errorf("shutdown: %w", err)
	}

	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}

	logger.Info("stopped")
	return nil
}

// parseFlags parses the command line. It returns (nil, nil) for --help so the
// caller can exit successfully after the usage text has been written.
func parseFlags(args []string, stdout, stderr io.Writer) (*options, error) {
	fs := flag.NewFlagSet("sb-render", flag.ContinueOnError)
	// Keep the FlagSet quiet: this function decides where help and errors go.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var opts options
	fs.StringVar(&opts.configDir, "config", "./config", "directory containing users/, modes/ and templates/")
	fs.StringVar(&opts.listen, "listen", "127.0.0.1:8080", "address to listen on (loopback required unless --allow-public)")
	fs.StringVar(&opts.logLevel, "log-level", "info", "log level: debug, info, warn or error")
	fs.DurationVar(&opts.shutdownTimeout, "shutdown-timeout", 10*time.Second, "graceful shutdown timeout")
	fs.BoolVar(&opts.allowPublic, "allow-public", false, "allow binding a non-loopback address (keep the service behind nginx)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeUsage(stdout, fs)
			return nil, nil
		}
		fmt.Fprintf(stderr, "sb-render: %v\n\n", err)
		writeUsage(stderr, fs)
		return nil, err
	}

	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	return &opts, nil
}

// writeUsage prints a double-dash flag listing; Go's flag package accepts both
// one and two dashes, but the documented form is clearer with two.
func writeUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "Usage: %s [flags]\n\nFlags:\n", fs.Name())
	fs.VisitAll(func(f *flag.Flag) {
		placeholder, usage := flag.UnquoteUsage(f)
		fmt.Fprintf(w, "  --%s", f.Name)
		if placeholder != "" {
			fmt.Fprintf(w, " %s", placeholder)
		}
		if f.DefValue != "" && f.DefValue != "false" {
			usage += fmt.Sprintf(" (default %q)", f.DefValue)
		}
		fmt.Fprintf(w, "\n        %s\n", usage)
	})
}

// parseLogLevel accepts the standard slog levels case-insensitively.
func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid --log-level %q: must be one of debug, info, warn, error", value)
	}
}

// validateListen refuses non-loopback addresses unless the operator opted in.
// The X-Auth-User header is trusted, so a public listener would let anyone
// impersonate any user.
func validateListen(addr string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --listen %q: %w", addr, err)
	}

	if isLoopbackHost(host) {
		return nil
	}
	if allowPublic {
		return nil
	}

	return fmt.Errorf("--listen %q is not a loopback address; pass --allow-public to bind a public interface", addr)
}

// isLoopbackHost reports whether host is "localhost", an IPv4 address in
// 127.0.0.0/8, or ::1. An empty host (":8080") is not loopback: it binds every
// interface.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	// Drop an IPv6 zone such as ::1%lo before parsing.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
