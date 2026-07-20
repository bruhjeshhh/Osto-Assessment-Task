// Package session manages authenticated CLI sessions, persisted so a
// session's expiry survives process restarts.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"cli-login-system/internal/dbgen"
	"cli-login-system/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrSessionNotFound = errors.New("session not found")
var ErrSessionExpired = errors.New("session expired")

type Manager struct {
	q       *dbgen.Queries
	timeout time.Duration
}

func NewManager(db dbgen.DBTX, timeout time.Duration) *Manager {
	return &Manager{q: dbgen.New(db), timeout: timeout}
}

// Create starts a new session for userID and persists it.
func (m *Manager) Create(ctx context.Context, userID int64) (*models.Session, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &models.Session{
		Token:     token,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.timeout),
	}
	err = m.q.CreateSession(ctx, dbgen.CreateSessionParams{
		Token:     sess.Token,
		UserID:    sess.UserID,
		CreatedAt: pgtype.Timestamptz{Time: sess.CreatedAt, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: sess.ExpiresAt, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// Validate looks up a session and confirms it hasn't expired.
func (m *Manager) Validate(ctx context.Context, token string) (*models.Session, error) {
	row, err := m.q.GetSession(ctx, token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}
	sess := &models.Session{
		Token:     row.Token,
		UserID:    row.UserID,
		CreatedAt: row.CreatedAt.Time,
		ExpiresAt: row.ExpiresAt.Time,
	}
	if sess.Expired(time.Now().UTC()) {
		return nil, ErrSessionExpired
	}
	return sess, nil
}

// Destroy removes a session (logout).
func (m *Manager) Destroy(ctx context.Context, token string) error {
	return m.q.DeleteSession(ctx, token)
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
