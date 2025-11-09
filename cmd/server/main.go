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

// setupLogger configures the application's structured logger (`slog`) based on the environment.
//
// In a production environment (`conf.IsProduction()` is true):
// - The logger uses a JSON handler, which outputs logs in a structured JSON format.
// - The logging level is set to `slog.LevelInfo`, meaning only informational messages and above are logged.
//
// In a development environment (otherwise):
// - The logger uses a Text handler, which outputs human-readable, colored text logs.
// - The logging level is set to `slog.LevelDebug`, providing more verbose output for debugging purposes.
//
// This function ensures that logs are formatted and filtered appropriately for different operational contexts.
func setupLogger(conf *config.Config) {
	var handler slog.Handler

	if conf.IsProduction() {
		// In production: structured JSON, level INFO
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	} else {
		// In development: colored text, level DEBUG
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	}

	slog.SetDefault(slog.New(handler))
}
