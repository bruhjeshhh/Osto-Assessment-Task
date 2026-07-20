package auth

import (
	"context"
	"errors"
	"time"

	"cli-login-system/internal/dbgen"
	"cli-login-system/internal/models"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUsernameTaken = errors.New("username already taken")

// Store wraps sqlc-generated queries and translates between pgtype values
// and the plain domain models used by the rest of the app.
type Store struct {
	q *dbgen.Queries
}

func NewStore(db dbgen.DBTX) *Store {
	return &Store{q: dbgen.New(db)}
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string, now time.Time) (*models.User, error) {
	row, err := s.q.CreateUser(ctx, dbgen.CreateUserParams{
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    toTimestamptz(now),
	})
	if err != nil {
		if isUniqueConstraintErr(err) {
			return nil, ErrUsernameTaken
		}
		return nil, err
	}
	return toUser(row), nil
}

func (s *Store) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	row, err := s.q.GetUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return toUser(row), nil
}

func (s *Store) GetByID(ctx context.Context, id int64) (*models.User, error) {
	row, err := s.q.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return toUser(row), nil
}

// RegisterFailedAttempt increments the failure counter and, once it
// crosses maxAttempts, sets a lockout expiring after lockoutDuration.
func (s *Store) RegisterFailedAttempt(ctx context.Context, userID int64, maxAttempts int, lockoutDuration time.Duration, now time.Time) error {
	attempts, err := s.q.IncrementFailedAttempts(ctx, userID)
	if err != nil {
		return err
	}
	if int(attempts) >= maxAttempts {
		lockedUntil := now.Add(lockoutDuration)
		return s.q.LockUser(ctx, dbgen.LockUserParams{
			ID:          userID,
			LockedUntil: toTimestamptz(lockedUntil),
		})
	}
	return nil
}

// ResetFailedAttempts clears the failure counter and any lockout, used on successful login.
func (s *Store) ResetFailedAttempts(ctx context.Context, userID int64) error {
	return s.q.ResetFailedAttempts(ctx, userID)
}

func (s *Store) UpdateLastLogin(ctx context.Context, userID int64, now time.Time) error {
	return s.q.UpdateLastLogin(ctx, dbgen.UpdateLastLoginParams{
		ID:        userID,
		LastLogin: toTimestamptz(now),
	})
}

func (s *Store) SetTOTPSecret(ctx context.Context, userID int64, secret string, enabled bool) error {
	return s.q.SetTOTPSecret(ctx, dbgen.SetTOTPSecretParams{
		ID:          userID,
		TotpSecret:  &secret,
		TotpEnabled: enabled,
	})
}

func (s *Store) DisableTOTP(ctx context.Context, userID int64) error {
	return s.q.DisableTOTP(ctx, userID)
}

func toUser(row dbgen.User) *models.User {
	u := &models.User{
		ID:             row.ID,
		Username:       row.Username,
		PasswordHash:   row.PasswordHash,
		CreatedAt:      row.CreatedAt.Time,
		TOTPEnabled:    row.TotpEnabled,
		FailedAttempts: int(row.FailedAttempts),
	}
	if row.TotpSecret != nil {
		u.TOTPSecret = *row.TotpSecret
	}
	if row.LockedUntil.Valid {
		t := row.LockedUntil.Time
		u.LockedUntil = &t
	}
	if row.LastLogin.Valid {
		t := row.LastLogin.Time
		u.LastLogin = &t
	}
	return u
}

func toTimestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func isUniqueConstraintErr(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" // unique_violation
}
