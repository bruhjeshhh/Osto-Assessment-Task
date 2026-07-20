// Command cli is the entrypoint for the containerized CLI login system.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/cli"
	"cli-login-system/internal/db"
	"cli-login-system/internal/session"
)

func main() {
	ctx := context.Background()

	dbURL := getenv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")
	maxAttempts := getenvInt("MAX_LOGIN_ATTEMPTS", 5)
	lockoutMinutes := getenvInt("LOCKOUT_MINUTES", 15)
	sessionMinutes := getenvInt("SESSION_TIMEOUT_MINUTES", 15)
	bcryptCost := getenvInt("BCRYPT_COST", 12)
	totpIssuer := getenv("TOTP_ISSUER", "CLI Login System")
	historyFile := getenv("HISTORY_FILE", "/data/.cli_login_history")

	pool, err := db.Open(ctx, dbURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to connect to database:", err)
		os.Exit(1)
	}
	defer pool.Close()

	store := auth.NewStore(pool)
	authSvc := auth.NewService(store, auth.Config{
		BcryptCost:       bcryptCost,
		MaxLoginAttempts: maxAttempts,
		LockoutDuration:  time.Duration(lockoutMinutes) * time.Minute,
		SessionTimeout:   time.Duration(sessionMinutes) * time.Minute,
		TOTPIssuer:       totpIssuer,
	})
	sessions := session.NewManager(pool, time.Duration(sessionMinutes)*time.Minute)

	app, err := cli.New(authSvc, store, sessions, historyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to start CLI:", err)
		os.Exit(1)
	}
	defer app.Close()

	app.Run()
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
