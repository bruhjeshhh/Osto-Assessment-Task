-- name: CreateUser :one
INSERT INTO users (username, password_hash, created_at, totp_enabled, failed_attempts)
VALUES ($1, $2, $3, FALSE, 0)
RETURNING *;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: IncrementFailedAttempts :one
UPDATE users
SET failed_attempts = failed_attempts + 1
WHERE id = $1
RETURNING failed_attempts;

-- name: LockUser :exec
UPDATE users
SET locked_until = $2
WHERE id = $1;

-- name: ResetFailedAttempts :exec
UPDATE users
SET failed_attempts = 0, locked_until = NULL
WHERE id = $1;

-- name: UpdateLastLogin :exec
UPDATE users
SET last_login = $2
WHERE id = $1;

-- name: SetTOTPSecret :exec
UPDATE users
SET totp_secret = $2, totp_enabled = $3
WHERE id = $1;

-- name: DisableTOTP :exec
UPDATE users
SET totp_secret = NULL, totp_enabled = FALSE
WHERE id = $1;
