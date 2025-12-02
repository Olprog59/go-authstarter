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

	"github.com/Olprog59/go-authstarter/internal/app"
	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/logging"
	"github.com/Olprog59/go-authstarter/internal/transport/web"
)

// init configures standard logger flags / Configure les flags du logger standard
func init() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.LstdFlags)
}

// main is the application entry point / Point d'entrée de l'application
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run initializes and starts the HTTP server / Initialise et démarre le serveur HTTP
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

// logStartupInfo displays startup information / Affiche les informations de démarrage
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

// setupLogger configures structured logger / Configure le logger structuré
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
