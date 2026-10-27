// Package server exposes the render pipeline over HTTP.
//
// The service is meant to sit behind nginx: nginx performs Basic Auth and
// forwards the authenticated username in the X-Auth-User header. This package
// does no authentication of its own; it trusts that header because the listener
// is bound to loopback and only nginx can reach it.
package server

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"sing-box-template-renderer/internal/render"
)

const (
	contentTypeJSON = "application/json; charset=utf-8"
	contentTypeText = "text/plain; charset=utf-8"
)

// ConfigLoader resolves the user, mode, and base template for one request.
// *render.Loader is the production implementation; tests can substitute a
// fake to exercise specific error paths.
type ConfigLoader interface {
	Load(name, inbound string) (render.Config, error)
}

type server struct {
	loader ConfigLoader
	logger *slog.Logger
}

// New builds the Gin engine with the /render and /healthz routes. A nil logger
// falls back to slog.Default.
func New(loader ConfigLoader, logger *slog.Logger) *gin.Engine {
	if logger == nil {
		logger = slog.Default()
	}

	gin.SetMode(gin.ReleaseMode)

	s := &server{loader: loader, logger: logger}

	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(requestLogger(logger))

	engine.GET("/render", s.handleRender)
	engine.HEAD("/render", s.handleRender)
	engine.GET("/healthz", handleHealthz)
	engine.HEAD("/healthz", handleHealthz)

	return engine
}

// handleRender renders a fresh configuration for the requesting user. It is
// registered for both GET and HEAD; HEAD performs the same work so it returns
// the same validators (ETag) while writing no body.
func (s *server) handleRender(c *gin.Context) {
	user := strings.TrimSpace(c.GetHeader("X-Auth-User"))
	if user == "" {
		writeError(c, http.StatusUnauthorized, "unauthorized")
		return
	}

	// An empty inbound is passed through unchanged; the loader defaults it to
	// "tun". The header is the only identity source: query parameters never
	// select a user.
	inbound := c.Query("inbound")

	cfg, err := s.loader.Load(user, inbound)
	if err != nil {
		status, message := errorStatus(err)
		writeError(c, status, message)
		return
	}

	body, err := render.Render(cfg.Template, user, cfg.User, cfg.Mode)
	if err != nil {
		// Never surface template contents or filesystem paths to the client.
		writeError(c, http.StatusInternalServerError, "render failed")
		return
	}

	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`

	c.Header("Content-Type", contentTypeJSON)
	c.Header("Cache-Control", "private, no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("ETag", etag)

	if etagMatches(c.GetHeader("If-None-Match"), etag) {
		c.Status(http.StatusNotModified)
		return
	}

	if c.Request.Method == http.MethodHead {
		// A HEAD response advertises the length the GET body would have but
		// writes nothing.
		c.Header("Content-Length", strconv.Itoa(len(body)))
		c.Status(http.StatusOK)
		return
	}

	c.Data(http.StatusOK, contentTypeJSON, body)
}

// handleHealthz reports process liveness. It intentionally touches no config.
func handleHealthz(c *gin.Context) {
	c.Header("Content-Type", contentTypeText)
	c.Header("Cache-Control", "private, no-store")
	c.Header("X-Content-Type-Options", "nosniff")

	if c.Request.Method == http.MethodHead {
		c.Header("Content-Length", "3")
		c.Status(http.StatusOK)
		return
	}

	c.String(http.StatusOK, "ok\n")
}

// writeError emits a status-only response for HEAD and a small JSON envelope
// for GET. Messages are deliberately generic: loader and template errors can
// contain filesystem paths, so they are logged nowhere and never echoed.
func writeError(c *gin.Context, status int, message string) {
	c.Header("Cache-Control", "private, no-store")
	c.Header("X-Content-Type-Options", "nosniff")

	if c.Request.Method == http.MethodHead {
		c.Status(status)
		return
	}

	c.JSON(status, gin.H{"error": message})
}

// errorStatus maps typed loader errors to HTTP status codes. Anything
// unrecognized is treated as a server-side render failure.
func errorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, render.ErrInvalidName):
		return http.StatusBadRequest, "invalid request"
	case errors.Is(err, render.ErrTproxyNotAllowed):
		return http.StatusForbidden, "tproxy not allowed"
	case errors.Is(err, render.ErrUnknownUser), errors.Is(err, render.ErrUnknownMode):
		return http.StatusNotFound, "not found"
	default:
		// Includes render.ErrUnknownTemplate and render.ErrInvalidConfig.
		return http.StatusInternalServerError, "render failed"
	}
}

// etagMatches reports whether an If-None-Match header selects etag. It accepts
// the special "*" value, weak validators (W/"..."), and comma-separated lists.
// Malformed input simply does not match; the parser never panics.
func etagMatches(header, etag string) bool {
	for _, token := range strings.Split(header, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if token == "*" {
			return true
		}
		token = strings.TrimSpace(strings.TrimPrefix(token, "W/"))
		if token == etag {
			return true
		}
	}
	return false
}

// requestLogger logs one structured record per request with the status, the
// time spent, and the nginx-supplied username. It never logs request bodies.
func requestLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		logger.LogAttrs(c.Request.Context(), slog.LevelInfo, "http request",
			slog.String("method", c.Request.Method),
			slog.String("path", c.Request.URL.Path),
			slog.Int("status", c.Writer.Status()),
			slog.Duration("duration", time.Since(start)),
			slog.String("user", c.GetHeader("X-Auth-User")),
		)
	}
}
