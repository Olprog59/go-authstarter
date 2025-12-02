[Documentation en Français](README.fr.md)

# GoAuthStarter

This repository serves as a robust and secure authentication template built with Go, designed for rapid integration into future web applications. It provides a solid foundation for user management, ensuring common security practices are implemented from the start.

### Features

- **User Registration & Login:** Secure user signup and sign-in flows.
- **JWT-based Authentication:** Utilizes JSON Web Tokens for stateless authentication.
- **Refresh Tokens:** Implements refresh tokens for enhanced security and session management with token rotation.
- **Email Verification:** Includes a flow for verifying user email addresses.
- **Secure Password Handling:** Stores passwords securely using bcrypt hashing (cost 12).
- **CSRF Protection:** Cross-Site Request Forgery protection for web forms and API calls.
- **Rate Limiting:** Multi-tier rate limiting (global, strict, per-user) to prevent abuse and brute-force attacks.
- **Account Lockout:** Automatic account locking after failed login attempts (5 attempts = 15 minute lockout).
- **Token Binding:** Refresh tokens are bound to client IP and User-Agent for enhanced security.
- **Role-Based Access Control (RBAC):** Hierarchical role system (user, moderator, admin) with JWT-based authorization.
- **Prometheus Metrics:** Complete observability with metrics for authentication, HTTP, security, and system health.
- **Health Checks:** Kubernetes-ready health and readiness endpoints for monitoring.
- **Database:** Uses SQLite with WAL mode for optimal concurrency and performance.
- **Structured Project Layout:** Follows hexagonal architecture for maintainability and testability.

### Technologies Used

- **Go:** The primary language for the backend.
- **SQLite:** Lightweight SQL database for data persistence.
- **JWT (JSON Web Tokens):** For authentication.
- **Viper:** For configuration management.
- **Slog:** Structured logging.

### Getting Started

To get a local copy up and running, follow these simple steps:

1. **Clone the repository:**

    ```bash
    git clone https://github.com/Olprog59/go-authstarter.git
    cd go-authstarter
    ```

2. **Install dependencies:**

    ```bash
    go mod tidy
    ```

3. **Configure:** Copy `config.example.yaml` to `config.yaml` and adjust settings as needed.
4. **Run migrations:**

    ```bash
    # (Specific migration command will go here, e.g., using 'migrate' tool)
    ```

5. **Run the application:**

    ```bash
    go run cmd/server/main.go
    ```

### Usage

This template is intended to be a starting point. You can:

- Fork this repository and adapt it to your specific project needs.
- Integrate the authentication logic and handlers into an existing Go application.
- Use it as a reference for implementing secure authentication patterns.

### Database Backups

GoAuthStarter includes automatic database backup functionality:

- **Automatic Backups:** Scheduled backups at configurable intervals
- **Retention Policy:** Automatic cleanup of old backups based on retention days
- **SQLite Support:** Optimized for SQLite databases with WAL mode
- **Zero-Downtime:** Backups are performed without interrupting the application

**Configuration:**
```yaml
backup:
  enabled: true              # Enable automatic backups
  interval: "24h"            # Backup every 24 hours
  path: "./backups"          # Storage directory
  retention_days: 7          # Keep backups for 7 days
```

### Monitoring & Observability

GoAuthStarter includes a complete observability stack for production:

**Metrics (Prometheus):**
- **Authentication metrics:** Login attempts, registrations, email verifications, token refreshes
- **HTTP metrics:** Request rates, response times, status codes, active connections
- **Security metrics:** Rate limit hits, CSRF failures, token binding failures, account lockouts
- **System metrics:** Database connections, background task status
- Access: `GET /metrics`

**Logs (Grafana Loki):**
- **Centralized logging:** Structured JSON logs with full context
- **Real-time search:** Query logs by user, IP, endpoint, error, etc.
- **Log aggregation:** Track errors, user activity, system events
- **Grafana integration:** Unified interface for logs + metrics

**Quick Start:**
```bash
# Start monitoring stack (Prometheus, Loki, Grafana)
docker-compose up -d

# Access Grafana
open http://localhost:3000  # admin/admin
```

### API Endpoints

**Public Endpoints:**
- `POST /api/register` - User registration
- `POST /api/login` - User authentication
- `GET /verify?token=...` - Email verification
- `POST /api/resend-verification` - Resend verification email
- `POST /api/request-password-reset` - Request password reset email
- `POST /api/reset-password` - Reset password with token

**Authenticated Endpoints:**
- `POST /api/refresh` - Refresh access token (requires auth + CSRF)
- `GET /api/me` - Get current user (requires auth + CSRF)
- `POST /api/logout` - Logout and invalidate refresh token (requires auth + CSRF)
- `GET /` - Home page (requires auth)

**Moderator Endpoints:**
- `GET /api/moderator/stats` - Get user statistics (requires moderator or admin role)

**Admin Endpoints:**
- `GET /api/admin/users` - List all users with roles
- `DELETE /api/admin/users/{id}` - Delete a user
- `PATCH /api/admin/users/{id}/role` - Update user's role

**Monitoring:**
- `GET /health` - Health check (liveness)
- `GET /readiness` - Readiness check (database connectivity)
- `GET /metrics` - Prometheus metrics (requires admin authentication)
