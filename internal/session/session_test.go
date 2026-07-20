package session_test

import (
	"context"
	"os"
	"testing"
	"time"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/db"
	"cli-login-system/internal/session"
)

// Tests need a running Postgres, pointed to by TEST_DATABASE_URL. They're
// skipped automatically if it isn't set (e.g. in CI without a DB service).
func newTestManager(t *testing.T, timeout time.Duration) (*session.Manager, context.Context, int64, func()) {
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
	if _, err := pool.Exec(ctx, "TRUNCATE sessions, users RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}

	store := auth.NewStore(pool)
	user, err := store.CreateUser(ctx, "testuser", "hash", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	mgr := session.NewManager(pool, timeout)
	cleanup := func() {
		pool.Close()
	}
	return mgr, ctx, user.ID, cleanup
}

func TestSessionCreateAndValidate(t *testing.T) {
	mgr, ctx, userID, cleanup := newTestManager(t, time.Minute)
	defer cleanup()

	sess, err := mgr.Create(ctx, userID)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.Token == "" {
		t.Fatal("expected non-empty token")
	}

	got, err := mgr.Validate(ctx, sess.Token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.UserID != userID {
		t.Fatalf("expected user id %d, got %d", userID, got.UserID)
	}
}

func TestSessionExpiry(t *testing.T) {
	mgr, ctx, userID, cleanup := newTestManager(t, 20*time.Millisecond)
	defer cleanup()

	sess, err := mgr.Create(ctx, userID)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(40 * time.Millisecond)
	if _, err := mgr.Validate(ctx, sess.Token); err != session.ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestSessionDestroy(t *testing.T) {
	mgr, ctx, userID, cleanup := newTestManager(t, time.Minute)
	defer cleanup()

	sess, err := mgr.Create(ctx, userID)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := mgr.Destroy(ctx, sess.Token); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := mgr.Validate(ctx, sess.Token); err != session.ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}
