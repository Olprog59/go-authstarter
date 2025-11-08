package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Olprog59/go-fun/internal/app"
	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/transport/web"
)

func init() {
	log.SetFlags(log.Lshortfile | log.Ldate | log.LstdFlags)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}

	// Configurer le logger selon l'environnement
	setupLogger(cfg)

	// Afficher la configuration du rate limiter au démarrage
	logStartupInfo(cfg)

	// Initialize container with all dependencies
	container, err := app.NewContainer(cfg)
	if err != nil {
		return err
	}
	defer container.Close()

	// Setup HTTP server
	handler := web.NewHandler(container)
	mux := web.NewMux(handler, cfg)

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

// logStartupInfo affiche les informations de démarrage
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

// setupLogger configure le logger selon l'environnement
func setupLogger(conf *config.Config) {
	var handler slog.Handler

	if conf.IsProduction() {
		// En production : JSON structuré, level INFO
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	} else {
		// En développement : texte coloré, level DEBUG
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	}

	slog.SetDefault(slog.New(handler))
}
