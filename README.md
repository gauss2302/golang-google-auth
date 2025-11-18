# golang-google-auth

This service provides OAuth-based authentication flows (Google, Twitter), session management, and CSRF protection for API clients built with Gin and net/http handlers.

## Configuration

The application is configured entirely through environment variables. See `.env.example` for sample values.

| Variable | Description |
| --- | --- |
| `ENVIRONMENT` | `development` or `production`. |
| `PORT` | HTTP port to bind. |
| `DATABASE_URL` | PostgreSQL connection string. |
| `REDIS_URL` | Redis connection string used for rate limiting and sessions. |
| `JWT_SECRET` | Secret used to sign access tokens. |
| `GOOGLE_WEB_CLIENT_ID` / `GOOGLE_WEB_CLIENT_SECRET` / `GOOGLE_WEB_REDIRECT_URL` | Google OAuth configuration. |
| `TWITTER_CLIENT_ID` / `TWITTER_CLIENT_SECRET` / `TWITTER_REDIRECT_URL` | Twitter OAuth configuration. |
| `FRONTEND_URL` | URL of the consuming frontend. |
| `CSRF_KEY` | Base64-encoded signing key for CSRF tokens (use `GENERATE` in development). |
| `CSRF_TOKEN_TTL_SECONDS` | Maximum token age before rejection (defaults to 86,400 seconds). |
| `RATE_LIMIT_PER_MINUTE` / `RATE_LIMIT_INTERVAL_SECONDS` | Rate limiting configuration. |
| `COOKIE_SECURE` | Whether to set secure cookies. |

## CSRF protection flow

The server issues an HttpOnly cookie named `csrf_token` and rotates it on every request. Clients should fetch a submission-friendly copy from the dedicated endpoint and echo it back on write requests:

1. Call `GET /api/v1/csrf-token`.
   - The response sets/refreshes the HttpOnly `csrf_token` cookie used for server-side verification.
   - The JSON body includes a `csrf_token` field that mirrors the cookie value so the client can read it (e.g., to place in a header).
2. For unsafe requests (`POST`, `PUT`, `PATCH`, `DELETE`), include the token value in the `X-CSRF-Token` header (or `csrf_token` form field).
   - The middleware rejects requests when the header token is missing, mismatched with the cookie, expired beyond the configured TTL, or fails signature validation.
3. After a successful request, the server rotates the CSRF token and updates the HttpOnly cookie to limit reuse.

This approach supports double-submit validation while keeping the cookie inaccessible to client-side scripts.
