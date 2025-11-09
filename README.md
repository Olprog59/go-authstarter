[Documentation en Français](README.fr.md)

# Go Authentication Template

## English

This repository serves as a robust and secure authentication template built with Go, designed for rapid integration into future web applications. It provides a solid foundation for user management, ensuring common security practices are implemented from the start.

### Features

- **User Registration & Login:** Secure user signup and sign-in flows.
- **JWT-based Authentication:** Utilizes JSON Web Tokens for stateless authentication.
- **Refresh Tokens:** Implements refresh tokens for enhanced security and session management.
- **Email Verification:** Includes a flow for verifying user email addresses.
- **Secure Password Handling:** Stores passwords securely using industry-standard hashing.
- **CSRF Protection:** Cross-Site Request Forgery protection for web forms and API calls.
- **Rate Limiting:** Prevents abuse and brute-force attacks on authentication endpoints.
- **Database:** Uses SQLite for simplicity and ease of setup.
- **Structured Project Layout:** Follows common Go project layout conventions for maintainability.

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
   git clone https://github.com/your-username/go-authentication-template.git
   cd go-authentication-template
   ```

2. **Install dependencies:**

   ```bash
   go mod tidy
   ```

3. **Configure:** Copy `config.yml.example` to `config.yml` and adjust settings as needed.
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
