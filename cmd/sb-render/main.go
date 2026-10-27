// Command sb-render is the sing-box template renderer HTTP service.
//
// This is a scaffold: it parses its command-line flags and exits. The Gin
// server and the rendering pipeline are implemented in a later task.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	var (
		configDir       = flag.String("config", "./config", "directory containing users/, modes/ and templates/")
		listenAddr      = flag.String("listen", "127.0.0.1:8080", "address to listen on")
		logLevel        = flag.String("log-level", "info", "log level (debug, info, warn, error)")
		shutdownTimeout = flag.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown timeout")
	)

	flag.Parse()

	// The HTTP surface (GET/HEAD /render) is wired up in a later task. Building
	// the engine here keeps the Gin dependency in go.mod and verifies wiring.
	engine := gin.New()

	fmt.Fprintf(os.Stdout,
		"sb-render scaffold: config=%s listen=%s log-level=%s shutdown-timeout=%s routes=%d\n",
		*configDir, *listenAddr, *logLevel, *shutdownTimeout, len(engine.Routes()),
	)
}
