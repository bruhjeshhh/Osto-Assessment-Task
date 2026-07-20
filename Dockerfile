# --- Build stage ---
FROM golang:1.22-bookworm AS builder

# No cgo needed: pgx is a pure-Go Postgres driver.
ENV CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o /out/cli-login ./cmd/cli

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 appuser
WORKDIR /app

COPY --from=builder /out/cli-login /app/cli-login

# HISTORY_FILE lives in a mounted volume so readline history survives restarts.
RUN mkdir -p /data && chown appuser:appuser /data
VOLUME ["/data"]

ENV HISTORY_FILE=/data/.cli_login_history \
    MAX_LOGIN_ATTEMPTS=5 \
    LOCKOUT_MINUTES=15 \
    SESSION_TIMEOUT_MINUTES=15 \
    BCRYPT_COST=12 \
    TOTP_ISSUER="CLI Login System"
# DATABASE_URL is set in docker-compose.yml to point at the postgres service.

USER appuser

ENTRYPOINT ["/app/cli-login"]
