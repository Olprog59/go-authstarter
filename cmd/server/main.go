package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Olprog59/go-fun/internal/app"
	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/infrastructure/logging"
	"github.com/Olprog59/go-fun/internal/transport/web"
)

// init is a special Go function that runs before main.
// It's used here to configure the standard logger's output flags.
// The flags `log.Lshortfile`, `log.Ldate`, and `log.LstdFlags` add
// the file name and line number, the date, and the time to each log entry,
// which is useful for debugging.
func init() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.LstdFlags)
}

// main is the entry point of the application.
// It calls the `run` function to start the server and handles any fatal errors
// that occur during the application's lifecycle.
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run initializes and starts the HTTP server, handling configuration,
// dependency injection, database migrations, and graceful shutdown.
//
// The function performs the following high-level steps:
// 1.  **Load Configuration**: Reads application settings from `config.yml` or environment variables.
// 2.  **Setup Logger**: Configures the structured logger (`slog`) based on the environment (development/production).
// 3.  **Log Startup Info**: Displays key application settings like environment, port, and rate limiter status.
// 4.  **Initialize Container**: Sets up the Dependency Injection container, which includes
//     database connection, migrations, repositories, and services.
// 5.  **Setup HTTP Server**: Creates the main HTTP router (`mux`) and configures the `http.Server`
//     with timeouts and the defined routes.
// 6.  **Graceful Shutdown**: Sets up signal handling to gracefully shut down the server
//     upon receiving `SIGINT` or `SIGTERM` signals, ensuring all active connections are
//     drained within a specified timeout.
//
// Returns:
//   - An error if any critical setup or server operation fails.
//   - `nil` if the server shuts down successfully.
func run() error {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}

	// Configure the logger according to the environment
	setupLogger(cfg)

	// Display the rate limiter configuration on startup
	logStartupInfo(cfg)

	// Initialize container with all dependencies
	container, err := app.NewContainer(cfg)
	if err != nil {
		return err
	}
	defer container.Close()

	// Setup HTTP server
	handler := web.NewHandler(container)
	mux := web.NewMux(handler, cfg, container)

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("Server listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		log.Println("Shutdown signal received")
	}

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	log.Println("Shutting down server gracefully...")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}

	log.Println("Server stopped successfully")
	return nil
}

// logStartupInfo displays key application information to the console when the server starts.
// This includes the current environment, the port the server is listening on,
// and details about the rate limiter configuration.
//
// It provides immediate feedback on the application's operational parameters,
// which is useful for verification during deployment and debugging.
func logStartupInfo(conf *config.Config) {
	slog.Info("🚀 Starting application",
		"environment", conf.Environment,
		"port", conf.Server.Port,
	)

	if conf.RateLimiter.Enabled {
		slog.Info("🛡️  Rate limiter enabled",
			"global_rps", conf.RateLimiter.RPS,
			"global_burst", conf.RateLimiter.Burst,
		)

		if conf.IsProduction() {
			slog.Info("🔒 Production mode: auth endpoints will use stricter limits",
				"auth_rps", conf.RateLimiter.RPS/2,
				"auth_burst", conf.RateLimiter.Burst/2,
			)
		}
	} else {
		slog.Warn("⚠️  Rate limiter is DISABLED")
	}

	slog.Info("⏱️  Token durations",
		"access_token", conf.Auth.AccessTokenDuration,
		"refresh_token", conf.Auth.RefreshTokenDuration,
	)
}

// setupLogger configures the application's structured logger (`slog`) based on the configuration.
//
// The logger can write to two outputs:
// 1. Console (stdout) - For local debugging and container logs (docker logs)
// 2. Loki - For centralized log aggregation (via direct HTTP push)
//
// Configuration via config.yaml:
// - logging.level: debug, info, warn, error (default: info)
// - logging.format: text or json (default: text)
// - logging.loki_enabled: true/false (default: false)
// - logging.loki_url: Loki server URL (default: http://localhost:3100)
// - logging.loki_batch_size: Number of logs to batch before sending (default: 10)
//
// In development, typically use:
//   - Console with text format for readability
//   - Loki enabled for testing the monitoring stack
//
// In production, typically use:
//   - Console with JSON format for container log aggregation
//   - Loki enabled for centralized logging
//
// This function ensures that logs are formatted, filtered, and routed appropriately
// based on the application's configuration.
func setupLogger(conf *config.Config) {
	// Parse log level from config
	var level slog.Level
	switch strings.ToLower(conf.Logging.Level) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// Create console handler
	var consoleHandler slog.Handler
	if strings.ToLower(conf.Logging.Format) == "json" {
		consoleHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     level,
			AddSource: conf.IsProduction(),
		})
	} else {
		consoleHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	}

	// If Loki is enabled, create a multi-handler that sends to both console and Loki
	if conf.Logging.LokiEnabled {
		lokiHandler := logging.NewLokiHandler(
			conf.Logging.LokiURL,
			conf.Logging.LokiLabels,
			conf.Logging.LokiBatchSize,
			true,
			level,
		)

		// Use multiHandler to send to both console and Loki
		handler := &multiHandler{
			consoleHandler: consoleHandler,
			lokiHandler:    lokiHandler,
		}
		slog.SetDefault(slog.New(handler))

		slog.Info("📊 Logging configured",
			"level", level.String(),
			"format", conf.Logging.Format,
			"loki_enabled", true,
			"loki_url", conf.Logging.LokiURL,
		)
	} else {
		// Console only
		slog.SetDefault(slog.New(consoleHandler))

		slog.Info("📊 Logging configured",
			"level", level.String(),
			"format", conf.Logging.Format,
			"loki_enabled", false,
		)
	}
}

// multiHandler writes to both console and Loki.
type multiHandler struct {
	consoleHandler slog.Handler
	lokiHandler    slog.Handler
}

func (h *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.consoleHandler.Enabled(ctx, level) || h.lokiHandler.Enabled(ctx, level)
}

func (h *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	// Write to console
	if err := h.consoleHandler.Handle(ctx, record); err != nil {
		return err
	}
	// Write to Loki (non-blocking, errors are logged internally)
	_ = h.lokiHandler.Handle(ctx, record)
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &multiHandler{
		consoleHandler: h.consoleHandler.WithAttrs(attrs),
		lokiHandler:    h.lokiHandler.WithAttrs(attrs),
	}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	return &multiHandler{
		consoleHandler: h.consoleHandler.WithGroup(name),
		lokiHandler:    h.lokiHandler.WithGroup(name),
	}
}
