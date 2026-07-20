package auth

import (
	"context"
	"errors"
	"time"
	"unicode"

	"cli-login-system/internal/models"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is locked, try again later")
	ErrWeakPassword       = errors.New("password must be at least 8 characters and include a letter and a number")
	ErrInvalidUsername    = errors.New("username must be 3-32 characters, alphanumeric or underscore")
	ErrTOTPRequired       = errors.New("TOTP code required")
	ErrInvalidTOTP        = errors.New("invalid TOTP code")
	ErrTOTPAlreadyOn      = errors.New("2FA is already enabled")
	ErrTOTPNotEnabled     = errors.New("2FA is not enabled")
)

// Config holds the tunable security parameters, sourced from environment
// variables at startup (see cmd/cli/main.go).
type Config struct {
	BcryptCost       int
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	SessionTimeout   time.Duration
	TOTPIssuer       string
}

// Service implements the authentication use cases on top of a Store.
type Service struct {
	store *Store
	cfg   Config
}

func NewService(store *Store, cfg Config) *Service {
	return &Service{store: store, cfg: cfg}
}

// Register creates a new account after validating username/password rules.
func (s *Service) Register(ctx context.Context, username, password string) (*models.User, error) {
	if !validUsername(username) {
		return nil, ErrInvalidUsername
	}
	if !validPassword(password) {
		return nil, ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		return nil, err
	}
	return s.store.CreateUser(ctx, username, string(hash), time.Now().UTC())
}

// Login validates credentials (and TOTP code, if enabled) and returns the
// authenticated user. totpCode may be empty if the account has no 2FA.
func (s *Service) Login(ctx context.Context, username, password, totpCode string) (*models.User, error) {
	now := time.Now().UTC()

	user, err := s.store.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Don't leak whether the username exists.
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.IsLocked(now) {
		return nil, ErrAccountLocked
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		_ = s.store.RegisterFailedAttempt(ctx, user.ID, s.cfg.MaxLoginAttempts, s.cfg.LockoutDuration, now)
		return nil, ErrInvalidCredentials
	}

	if user.TOTPEnabled {
		if totpCode == "" {
			return nil, ErrTOTPRequired
		}
		if !totp.Validate(totpCode, user.TOTPSecret) {
			_ = s.store.RegisterFailedAttempt(ctx, user.ID, s.cfg.MaxLoginAttempts, s.cfg.LockoutDuration, now)
			return nil, ErrInvalidTOTP
		}
	}

	if err := s.store.ResetFailedAttempts(ctx, user.ID); err != nil {
		return nil, err
	}
	if err := s.store.UpdateLastLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}

	// user.LastLogin still holds the *previous* login time (fetched before
	// this login's UpdateLastLogin write), which is what the CLI should
	// display as "last login".
	user.FailedAttempts = 0
	user.LockedUntil = nil
	return user, nil
}

// EnableTOTP generates a new secret for the user and returns the secret and
// otpauth:// URL (for QR code generation); it is not persisted as enabled
// until ConfirmTOTP verifies the user actually has it set up.
func (s *Service) EnableTOTP(ctx context.Context, user *models.User) (secret string, otpauthURL string, err error) {
	if user.TOTPEnabled {
		return "", "", ErrTOTPAlreadyOn
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.TOTPIssuer,
		AccountName: user.Username,
	})
	if err != nil {
		return "", "", err
	}
	// Store the secret but keep 2FA disabled until confirmed.
	if err := s.store.SetTOTPSecret(ctx, user.ID, key.Secret(), false); err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// ConfirmTOTP verifies a code against the pending secret and, if valid,
// marks 2FA as enabled.
func (s *Service) ConfirmTOTP(ctx context.Context, user *models.User, secret, code string) error {
	if !totp.Validate(code, secret) {
		return ErrInvalidTOTP
	}
	return s.store.SetTOTPSecret(ctx, user.ID, secret, true)
}

func (s *Service) DisableTOTP(ctx context.Context, user *models.User) error {
	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}
	return s.store.DisableTOTP(ctx, user.ID)
}

func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, r := range u {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

func validPassword(p string) bool {
	if len(p) < 8 {
		return false
	}
	var hasLetter, hasDigit bool
	for _, r := range p {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	return hasLetter && hasDigit
}
