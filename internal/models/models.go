package models

import "time"

// User represents a registered account.
type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	CreatedAt      time.Time
	TOTPSecret     string
	TOTPEnabled    bool
	FailedAttempts int
	LockedUntil    *time.Time
	LastLogin      *time.Time
}

// IsLocked reports whether the account is currently under a lockout.
func (u *User) IsLocked(now time.Time) bool {
	return u.LockedUntil != nil && now.Before(*u.LockedUntil)
}

// Session represents an authenticated CLI session.
type Session struct {
	Token     string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Expired reports whether the session is no longer valid at time now.
func (s *Session) Expired(now time.Time) bool {
	return now.After(s.ExpiresAt)
}
