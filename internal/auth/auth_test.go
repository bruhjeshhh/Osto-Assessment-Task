package auth_test

import (
	"context"
	"os"
	"testing"
	"time"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/db"

	"github.com/pquerna/otp/totp"
)

// Tests need a running Postgres, pointed to by TEST_DATABASE_URL. They're
// skipped automatically if it isn't set (e.g. in CI without a DB service).
func newTestService(t *testing.T) (*auth.Service, context.Context, func()) {
	t.Helper()
	connString := os.Getenv("TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, connString)
	if err != nil {
		t.Fatal(err)
	}
	// Each test starts from a clean slate.
	if _, err := pool.Exec(ctx, "TRUNCATE sessions, users RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}

	store := auth.NewStore(pool)
	svc := auth.NewService(store, auth.Config{
		BcryptCost:       4, // fast for tests
		MaxLoginAttempts: 3,
		LockoutDuration:  50 * time.Millisecond,
		SessionTimeout:   time.Minute,
		TOTPIssuer:       "TestApp",
	})
	cleanup := func() {
		pool.Close()
	}
	return svc, ctx, cleanup
}

func TestRegisterAndLogin(t *testing.T) {
	svc, ctx, cleanup := newTestService(t)
	defer cleanup()

	if _, err := svc.Register(ctx, "alice", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := svc.Register(ctx, "alice", "password123"); err != auth.ErrUsernameTaken {
		t.Fatalf("expected ErrUsernameTaken, got %v", err)
	}

	if _, err := svc.Login(ctx, "alice", "password123", ""); err != nil {
		t.Fatalf("login: %v", err)
	}

	if _, err := svc.Login(ctx, "alice", "wrong", ""); err != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestPasswordAndUsernameValidation(t *testing.T) {
	svc, ctx, cleanup := newTestService(t)
	defer cleanup()

	if _, err := svc.Register(ctx, "ab", "password123"); err != auth.ErrInvalidUsername {
		t.Fatalf("expected ErrInvalidUsername for short name, got %v", err)
	}
	if _, err := svc.Register(ctx, "validname", "short1"); err != auth.ErrWeakPassword {
		t.Fatalf("expected ErrWeakPassword for short password, got %v", err)
	}
	if _, err := svc.Register(ctx, "validname", "onlyletters"); err != auth.ErrWeakPassword {
		t.Fatalf("expected ErrWeakPassword for no-digit password, got %v", err)
	}
}

func TestAccountLockout(t *testing.T) {
	svc, ctx, cleanup := newTestService(t)
	defer cleanup()

	if _, err := svc.Register(ctx, "bob", "password123"); err != nil {
		t.Fatalf("register: %v", err)
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		_, lastErr = svc.Login(ctx, "bob", "wrongpass", "")
	}
	if lastErr != auth.ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials on 3rd try, got %v", lastErr)
	}

	// The account should now be locked even with the correct password.
	if _, err := svc.Login(ctx, "bob", "password123", ""); err != auth.ErrAccountLocked {
		t.Fatalf("expected ErrAccountLocked, got %v", err)
	}

	// After the lockout window passes, login should succeed again.
	time.Sleep(60 * time.Millisecond)
	if _, err := svc.Login(ctx, "bob", "password123", ""); err != nil {
		t.Fatalf("expected login to succeed after lockout expiry, got %v", err)
	}
}

func TestTOTPEnableAndLogin(t *testing.T) {
	svc, ctx, cleanup := newTestService(t)
	defer cleanup()

	user, err := svc.Register(ctx, "carol", "password123")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	secret, _, err := svc.EnableTOTP(ctx, user)
	if err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if err := svc.ConfirmTOTP(ctx, user, secret, code); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}

	// Login without a code should now require one.
	if _, err := svc.Login(ctx, "carol", "password123", ""); err != auth.ErrTOTPRequired {
		t.Fatalf("expected ErrTOTPRequired, got %v", err)
	}

	// Login with a fresh valid code should succeed.
	loginCode, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	loggedIn, err := svc.Login(ctx, "carol", "password123", loginCode)
	if err != nil {
		t.Fatalf("login with totp: %v", err)
	}
	if !loggedIn.TOTPEnabled {
		t.Fatalf("expected TOTPEnabled to be true")
	}

	// Disable and confirm plain login works again.
	if err := svc.DisableTOTP(ctx, loggedIn); err != nil {
		t.Fatalf("disable totp: %v", err)
	}
	if _, err := svc.Login(ctx, "carol", "password123", ""); err != nil {
		t.Fatalf("expected plain login to succeed after disabling 2FA, got %v", err)
	}
}
